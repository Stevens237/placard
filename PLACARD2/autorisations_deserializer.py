from django.core.serializers.json import Deserializer
from placard.models import Autorisations

def custom_deserialize_objects(stream_or_string, **options):
    objects = Deserializer(stream_or_string, **options)

    for obj in objects:
        if obj.object.get('identifier'):
            identifier = obj.object['identifier']
            if not Autorisations.objects.filter(identifier=identifier).exists():
                Autorisations.objects.create(**obj.object)

