from typing import Dict, Any, List, Optional
from common.models.base_agent import BaseAgent
from common.utils.database import db
from common.utils.message_queue import mq
import logging
import pytesseract
from PIL import Image
import io
import base64
import cv2
import numpy as np
from datetime import datetime

class OCRAgent(BaseAgent):
    """Agent responsible for extracting text from images using OCR."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__("ocr", config)
        self.supported_formats = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff']
        self.min_confidence = 60  # Minimum confidence score for OCR results

    async def initialize(self) -> None:
        """Initialize the OCR agent."""
        self.logger.info("Initializing OCR Agent")
        # Verify tesseract installation
        try:
            pytesseract.get_tesseract_version()
            self.logger.info("Tesseract initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing Tesseract: {str(e)}")
            raise

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process images for text extraction."""
        try:
            incident_id = data.get('incident_id')
            images = data.get('images', [])
            
            if not images:
                raise ValueError("No images provided for OCR analysis")

            # Process each image
            ocr_results = []
            for image_data in images:
                result = await self._process_single_image(image_data)
                if result:
                    ocr_results.append(result)

            # Aggregate results
            analysis_results = {
                'incident_id': incident_id,
                'ocr_results': ocr_results,
                'timestamp': datetime.utcnow().isoformat()
            }

            # Store results
            await db.update_analysis_result(incident_id, {
                'ocr_analysis': analysis_results
            })

            # Notify text analysis agent if text was found
            await self._notify_text_analysis(incident_id, ocr_results)

            return analysis_results

        except Exception as e:
            await self.handle_error(e)
            raise

    async def _process_single_image(self, image_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single image for text extraction."""
        try:
            # Extract image content
            image_content = self._get_image_content(image_data)
            if not image_content:
                return None

            # Convert to OpenCV format for preprocessing
            image_array = np.frombuffer(image_content, np.uint8)
            image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
            
            # Preprocess image
            preprocessed = self._preprocess_image(image)
            
            # Perform OCR
            ocr_result = self._perform_ocr(preprocessed)
            
            if not ocr_result['text'].strip():
                return None

            return {
                'source': image_data.get('source', 'unknown'),
                'format': image_data.get('format', 'unknown'),
                'ocr_result': ocr_result,
                'dimensions': {
                    'width': image.shape[1],
                    'height': image.shape[0]
                }
            }

        except Exception as e:
            self.logger.error(f"Error processing image: {str(e)}")
            return None

    def _get_image_content(self, image_data: Dict[str, Any]) -> Optional[bytes]:
        """Extract image content from various formats."""
        try:
            if 'base64' in image_data:
                return base64.b64decode(image_data['base64'])
            elif 'bytes' in image_data:
                return image_data['bytes']
            elif 'path' in image_data:
                with open(image_data['path'], 'rb') as f:
                    return f.read()
            else:
                self.logger.error("No valid image content found in image data")
                return None
        except Exception as e:
            self.logger.error(f"Error extracting image content: {str(e)}")
            return None

    def _preprocess_image(self, image: np.ndarray) -> np.ndarray:
        """Preprocess image for better OCR results."""
        try:
            # Convert to grayscale
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Apply thresholding to get black and white image
            _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            
            # Noise removal
            denoised = cv2.fastNlMeansDenoising(binary)
            
            # Dilation to make text more prominent
            kernel = np.ones((1, 1), np.uint8)
            dilated = cv2.dilate(denoised, kernel, iterations=1)
            
            return dilated

        except Exception as e:
            self.logger.error(f"Error preprocessing image: {str(e)}")
            return image

    def _perform_ocr(self, image: np.ndarray) -> Dict[str, Any]:
        """Perform OCR on the preprocessed image."""
        try:
            # Convert numpy array to PIL Image
            pil_image = Image.fromarray(image)
            
            # Perform OCR with additional configuration
            custom_config = f'--oem 3 --psm 6'
            ocr_data = pytesseract.image_to_data(pil_image, config=custom_config, output_type=pytesseract.Output.DICT)
            
            # Extract text and confidence scores
            text_blocks = []
            total_confidence = 0
            word_count = 0
            
            for i in range(len(ocr_data['text'])):
                if int(ocr_data['conf'][i]) > self.min_confidence:
                    word = ocr_data['text'][i].strip()
                    if word:
                        text_blocks.append({
                            'text': word,
                            'confidence': float(ocr_data['conf'][i]),
                            'bbox': {
                                'x': ocr_data['left'][i],
                                'y': ocr_data['top'][i],
                                'width': ocr_data['width'][i],
                                'height': ocr_data['height'][i]
                            }
                        })
                        total_confidence += float(ocr_data['conf'][i])
                        word_count += 1

            # Calculate average confidence
            avg_confidence = total_confidence / word_count if word_count > 0 else 0

            return {
                'text': ' '.join(block['text'] for block in text_blocks),
                'text_blocks': text_blocks,
                'average_confidence': avg_confidence,
                'word_count': word_count
            }

        except Exception as e:
            self.logger.error(f"Error performing OCR: {str(e)}")
            return {
                'text': '',
                'text_blocks': [],
                'average_confidence': 0,
                'word_count': 0
            }

    async def _notify_text_analysis(self, incident_id: str, ocr_results: List[Dict[str, Any]]) -> None:
        """Notify the text analysis agent about extracted text."""
        # Combine all extracted text
        all_text = ' '.join(
            result['ocr_result']['text']
            for result in ocr_results
            if result and result['ocr_result']['text']
        )

        if all_text.strip():
            await mq.publish('text_analysis', {
                'incident_id': incident_id,
                'content': all_text,
                'source': 'ocr',
                'confidence': sum(r['ocr_result']['average_confidence'] for r in ocr_results) / len(ocr_results)
            })

    async def cleanup(self) -> None:
        """Cleanup resources before shutting down."""
        self.logger.info("Cleaning up OCR Agent")
        # Additional cleanup if needed 