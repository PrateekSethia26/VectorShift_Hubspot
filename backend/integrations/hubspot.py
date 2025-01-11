# slack.py
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import urllib.parse
import secrets
import json
import base64
import httpx
import asyncio
import requests
from datetime import datetime

from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

CLIENT_ID = '57113d4b-613a-4f92-bed3-ea095e389e9a'   # This is not safe so it is recommended to save the credentials in the env file or local config file which should not be pushed. 
CLIENT_SECRET = '88916c4c-5ec1-4cd1-856b-2efa59a56aa7'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
TOKEN_ENDPOINT = "https://api.hubapi.com/oauth/v1/token"
SCOPES = ['oauth','crm.objects.contacts.read']

AUTHORIZATION_URL = 'https://app.hubspot.com/oauth/authorize?'

async def authorize_hubspot(user_id, org_id):
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': ' '.join(SCOPES),  # Space-separated string, not encoded here
    }
    state_data = {
        'state': secrets.token_urlsafe(32), # Generating randomly
        'user_id': user_id,
        'org_id': org_id
    }
    url = AUTHORIZATION_URL+urllib.parse.urlencode(params)
    # print(url)

    encoded_state = json.dumps(state_data)

    # Base64 encode the JSON string
    base64_encoded_state = base64.b64encode(encoded_state.encode('utf-8')).decode('utf-8')

    await add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', base64_encoded_state, expire=600)
    return f'{url}&state={base64_encoded_state}'


async def oauth2callback_hubspot(request: Request):
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    
    base64_decoded_state = base64.b64decode(encoded_state).decode('utf-8')

    decoded_state = json.loads(base64_decoded_state)
    user_id = decoded_state['user_id']
    org_id = decoded_state['org_id']

    saved_state = await get_value_redis(f'hubspot_state:{org_id}:{user_id}')
    
    if saved_state.decode('utf-8') != encoded_state :
        raise HTTPException(status_code=400, detail='State does not match.')
    
    response = await tokenGeneration(code,user_id, org_id)
    print(response)

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response), expire=600)

    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)    

async def get_hubspot_credentials(user_id, org_id):
    
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials

async def create_integration_item_metadata_object(response_json):
    integration_items = []
    
    for contact in response_json.get('results', []):
        props = contact.get('properties', {})
        
        # Create name from first and last name
        name = f"{props.get('firstname', '')} {props.get('lastname', '')}".strip()
        
        # Convert timestamps to datetime objects
        creation_time = datetime.fromisoformat(contact['createdAt'].replace('Z', '+00:00'))
        last_modified_time = datetime.fromisoformat(contact['updatedAt'].replace('Z', '+00:00'))
        
        item = IntegrationItem(
            id=contact['id'],
            type='contact',  # Set type as contact since these are HubSpot contacts
            directory=False,  # Contacts are not directories
            name=name,
            creation_time=creation_time,
            last_modified_time=last_modified_time,
            url=f"'https://api.hubapi.com/crm/v3/objects/contacts/{contact['id']}",  # Construct HubSpot contact URL
            visibility=not contact.get('archived', False)
        )
        
        integration_items.append(item)
    
    return integration_items

async def get_items_hubspot(credentials : str):
    creds = json.loads(credentials)
    # print(creds)

    response = requests.get(
        'https://api.hubapi.com/crm/v3/objects/contacts',
        headers={
            'Authorization': f'Bearer {creds.get("access_token")}',
        },
    )

    return await create_integration_item_metadata_object(response.json())
    # return response.json()

async def tokenGeneration(code,user_id, org_id) : 
     # Define the URL and headers
    headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8"
    }

    # Define the payload
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code": code
    }

     # Perform the async POST request
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(TOKEN_ENDPOINT,headers = headers , data = payload)   # Reducing variable counts as this contains whole url things

            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),  # old_state

            response.raise_for_status()  # Raise exception for HTTP errors
            return response.json()
        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"An error occurred while making the request: {e}")
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=response.status_code, detail=f"HTTP error: {response.text}")
