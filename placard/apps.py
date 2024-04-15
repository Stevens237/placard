# Dans le fichier apps.py de votre application "placard"
from django.apps import AppConfig

class PlacardConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'placard'

    #def ready(self):
        # Importer le module signals ici pour éviter l'erreur AppRegistryNotReady
       # import placard.signals
