from django.contrib import admin
from .models import AutorisationsGroup, Autorisations, Role, Accounts,AccountGroup, Projects

admin.site.register(AutorisationsGroup)
admin.site.register(Autorisations)
admin.site.register(Role)
admin.site.register(Accounts)
admin.site.register(AccountGroup)
admin.site.register(Projects)



