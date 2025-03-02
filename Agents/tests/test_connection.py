import os
import sys
import asyncio
import redis
from dotenv import load_dotenv
import httpx
import json

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_redis_connection():
    """Test Redis connection."""
    try:
        # Create Redis connection
        r = redis.Redis(
            host=os.getenv('REDIS_HOST'),
            port=int(os.getenv('REDIS_PORT')),
            password=os.getenv('REDIS_PASSWORD'),
            decode_responses=True
        )
        
        # Test connection
        r.ping()
        print("✅ Redis connection successful!")
        
        # Test set/get
        r.set('test_key', 'test_value')
        value = r.get('test_key')
        assert value == 'test_value'
        print("✅ Redis operations working!")
        
        # Cleanup
        r.delete('test_key')
        
    except Exception as e:
        print(f"❌ Redis connection failed: {str(e)}")
        raise

async def test_supabase_connection():
    """Test Supabase connection."""
    try:
        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_KEY')
        
        if not supabase_url or not supabase_key:
            raise ValueError("Supabase credentials not found in environment variables")
        
        # Test connection by making a simple request
        async with httpx.AsyncClient() as client:
            headers = {
                'apikey': supabase_key,
                'Authorization': f'Bearer {supabase_key}'
            }
            
            response = await client.get(
                f"{supabase_url}/rest/v1/phishing_incidents?select=count",
                headers=headers
            )
            
            if response.status_code == 200:
                print("✅ Supabase connection successful!")
                print(f"Response: {response.text}")
            else:
                raise Exception(f"Failed to connect to Supabase. Status code: {response.status_code}")
        
    except Exception as e:
        print(f"❌ Supabase connection failed: {str(e)}")
        raise

async def main():
    """Main test function."""
    # Load environment variables
    load_dotenv()
    
    print("\nTesting connections...")
    print("-" * 50)
    
    try:
        # Test Redis
        print("\nTesting Redis connection:")
        test_redis_connection()
        
        # Test Supabase
        print("\nTesting Supabase connection:")
        await test_supabase_connection()
        
        print("\n✨ All connections successful!")
        
    except Exception as e:
        print(f"\n❌ Connection tests failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 