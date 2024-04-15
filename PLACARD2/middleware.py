
import jwt
from django.conf import settings
from django.http import JsonResponse

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response



    def __call__(self, request):
      #  excluded_paths = ['/api/login', '/api/accounts/', '/password/define/request/']
        excluded_paths = ['/api/login', '/api/accounts/', '/password/define/', 
                          '/api/password/define/request/', '/password/reset/']


        if any(request.path.startswith(path) for path in excluded_paths):
            # Laisser passer la requête sans vérifier l'authentification
            response = self.get_response(request)
            return response

        authorization_header = request.headers.get('Authorization')
        

        if not authorization_header or not authorization_header.startswith('Bearer '):
            return JsonResponse({"error": "Authentication required."}, status=401)

        token = authorization_header.split(' ')[1]
        


        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])

            # logique pour vérifier la validité du token

            request.user_id = decoded_token.get('id')
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token has expired."}, status=401)
        except jwt.InvalidTokenError as invalidTokenError:
            return JsonResponse({"error": str(invalidTokenError)}, status=401)
        
      #  print(request.headers)

        response = self.get_response(request)
        
        return response

