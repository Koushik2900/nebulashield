import aiohttp
import json

class AdaptiveLLMAnalyzer:
    def __init__(self, cache_size=100):
        self.cache = {}
        self.cache_size = cache_size

    async def analyze_payload(self, payload, context):
        cache_key = self._create_cache_key(payload, context)
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        response = await self._query_ollama(payload, context)
        self._update_cache(cache_key, response)
        return response

    def _create_cache_key(self, payload, context):
        return json.dumps({"payload": payload, "context": context})

    async def _query_ollama(self, payload, context):
        async with aiohttp.ClientSession() as session:
            async with session.post('https://api.ollama.com/query', json={"payload": payload, "context": context}) as response:
                return await response.json()

    def _update_cache(self, key, value):
        if len(self.cache) >= self.cache_size:
            self.cache.pop(next(iter(self.cache)))  # Remove the oldest item
        self.cache[key] = value
