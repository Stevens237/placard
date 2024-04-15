import uuid
from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver
from user_agents import parse
from django.utils import timezone
from django.utils.text import slugify
from django.utils.crypto import get_random_string
from django.conf import settings

from .status import Status


from datetime import datetime


class StringUUIDField(models.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('max_length', 36)
        super().__init__(*args, **kwargs)

    def to_python(self, value):
        return value

    def from_db_value(self, value, expression, connection):
        return str(value)

    def get_prep_value(self, value):
        return str(value)



class AutorisationsGroup(models.Model):
    display_name = models.CharField(max_length=255)
    identifier = models.CharField(max_length=255, unique=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.identifier:
            self.identifier = self.generate_custom_identifier()

        super().save(*args, **kwargs)

    def generate_custom_identifier(self):
        # Générer un slug basé sur le nom de la fomnctionnalité
        slug = slugify(self.display_name)

        # Vérifier si le slug existe déjà
        existing_slugs = AutorisationsGroup.objects.filter(identifier__startswith=slug).values_list('identifier', flat=True)
        if self.identifier in existing_slugs:
            # Si le slug existe déjà, on ajoute un suffixe numérique pour le rendre unique
            suffix = 1
            while f"{slug}-{suffix}" in existing_slugs:
                suffix += 1
            slug = f"{slug}_{suffix}"

        return slug

    def __str__(self):
        return self.display_name
    

class Autorisations(models.Model):
    display_name = models.CharField(max_length=255)
    autorisations_identifier = models.CharField(primary_key=True, max_length=255, unique=True, blank=True, editable=False)
    

    def __str__(self):
        return self.display_name

class Audit(models.Model):
    createdBy = models.ForeignKey('Accounts', on_delete=models.CASCADE, related_name='created_%(class)s', blank=True)
    lastUpdatedBy = models.ForeignKey('Accounts', on_delete=models.CASCADE, related_name='updated_%(class)s', blank=True)
    createdAt = models.DateTimeField(default=timezone.now, blank=True)
    lastUpdatedAt = models.DateTimeField(auto_now=True, blank=True)

    class Meta:
        abstract = True

class Role(Audit):
    display_name = models.CharField(max_length=255)
    autorisations = models.ManyToManyField(Autorisations, related_name='roles')
    role_identifier = StringUUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    status = models.CharField(max_length=20, choices=[(status, status) for status in [Status.ACTIVATED, Status.DEACTIVATED]], default=Status.ACTIVATED)

    def __str__(self):
        return self.display_name

    
class Token(models.Model):
    token = models.CharField(max_length=255, unique=True)
    created_for = models.CharField(max_length=255)
    valid_until = models.DateTimeField()
    accounts = models.ForeignKey('Accounts', on_delete=models.CASCADE)
    token_usage = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.token} - {self.accounts.username}"
   
    @classmethod
    def create_token_for_accounts(cls, accounts):
        token = cls()
        token.token = str(uuid.uuid4())
        token.created_for = f" token for   {accounts.email}"
        token.valid_until = datetime.now() + timedelta(days=5)
        token.accounts = accounts
        token.token_usage = " to define the password"  
        token.save()
        accounts.tokens = token.token
        return token
    
class CustomUserManager(BaseUserManager):
    
    def create_accounts(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')

        username = email  # Utiliser l'email comme nom d'utilisateur

        user = self.model(username=username, email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_accounts(email, password, **extra_fields)


  
class CustomBaseUser(AbstractBaseUser, PermissionsMixin):

    accreditations = models.CharField(max_length=200, blank=True)
    last_updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, related_name='created_users')
    last_updated_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, related_name='updated_users')
    created_at = models.DateTimeField(auto_now_add=True)
    roles = models.ManyToManyField(Role, related_name='assigned_users',  blank=True)
    last_login=models.DateTimeField(verbose_name='last login', auto_now_add=True)
    date_joined=models.DateTimeField(verbose_name='date joined', auto_now_add=True)
    Active= models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
   
class Accounts(CustomBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    username = models.CharField(max_length=150, unique=True)
    user_identifier = StringUUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    status = models.CharField(max_length=20, choices=[(status, status) for status in [Status.ACTIVATED, Status.DEACTIVATED]], default=Status.ACTIVATED)
    class Meta:
        verbose_name_plural = "Accounts"

    objects = CustomUserManager()
    REQUIRED_FIELDS = ['first_name', 'last_name']
    USERNAME_FIELD = 'email'

    def __str__(self):
        return self.email
    



class AccountGroup(CustomBaseUser, PermissionsMixin):
    display_name = models.CharField(max_length=128)
    group_identifier = StringUUIDField(primary_key=True, default=uuid.uuid4, editable=False, blank=True)
    accounts = models.ManyToManyField(Accounts, related_name='assigned_groups', blank=True)
    autorisations = models.ManyToManyField(Autorisations, related_name='groups', blank=True)
    status = models.CharField(max_length=20, choices=[(status, status) for status in [Status.ACTIVATED, Status.DEACTIVATED]], default=Status.ACTIVATED)
   

    def __str__(self):
        return self.display_name

    def add_account(self, account):
        if account not in self.accounts.all():
            self.accounts.add(account)

    def remove_account(self, account):
        if account in self.accounts.all():
            self.accounts.remove(account)

    def add_autorisation(self, autorisation):
        self.autorisations.add(autorisation)

    def remove_autorisation(self, autorisation):
        self.autorisations.remove(autorisation)

    def add_role(self, role):
        self.group_roles.add(role)

    def remove_role(self, role):
        self.group_roles.remove(role)   




class UsersGroupRelationship(models.Model):


    ACTIVATED = 'activated'
    DEACTIVATED = 'deactivated'

    STATUS_CHOICES = [
        (ACTIVATED, 'Activated'),
        (DEACTIVATED, 'Deactivated'),
    ]


    accounts_group_identifier = models.ForeignKey(AccountGroup, on_delete=models.CASCADE, related_name='group_accounts')
    account_identifier = models.ForeignKey(Accounts, on_delete=models.CASCADE, related_name='user_groups')
    statut_in_Group  = models.CharField(max_length=20,choices=STATUS_CHOICES,default=ACTIVATED)
    createdBy = models.ForeignKey('Accounts', on_delete=models.CASCADE, related_name='created_%(class)s', blank=True)
    lastUpdatedBy = models.ForeignKey('Accounts', on_delete=models.CASCADE, related_name='updated_%(class)s', blank=True)
    createdAt = models.DateTimeField(default=timezone.now, blank=True)
    lastUpdatedAt = models.DateTimeField(auto_now=True, blank=True)
    
    

    class Meta:
        db_table = 'users_group_relationship'  # Nom de table personnalisé
        

    def __str__(self):
        return f"{self.user.email} - {self.group.display_name}"







# classe de jointure entre Accounts et AccountGroup      
           
    


   
class GroupRole(models.Model):
    account_group = models.ForeignKey(AccountGroup, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    role_identifier = StringUUIDField(default=uuid.uuid4, editable=False)

    class Meta:
        unique_together = ('account_group', 'role')

class Hierarchy(models.Model):
    hierachy_identifier = StringUUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    hierarchy_name = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=[(status, status) for status in [Status.ACTIVATED, Status.DEACTIVATED]], default=Status.ACTIVATED)

    def __str__(self):
        return self.hierarchy_name

class HierarchyItem(models.Model):
    HieraItem_identifier = StringUUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    level = models.IntegerField(choices=[(1, 'Level 1'), (2, 'Level 2'), (3, 'Level 3'), (4, 'Level 4'), (5, 'Level 5'), (6, 'Level 6')])
    name = models.CharField(max_length=255)
    hierarchy_identifier = models.ForeignKey(Hierarchy, on_delete=models.CASCADE)
    parent_identifier = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    status = models.CharField(max_length=20, choices=[(status, status) for status in [Status.ACTIVATED, Status.DEACTIVATED]], default=Status.ACTIVATED)

    def __str__(self):
        return self.name
    


class Projects(models.Model):
    
    Project_identifier = StringUUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    Project_name = models.CharField(max_length=100)
    hierachy_identifier = models.ForeignKey(Hierarchy, on_delete=models.CASCADE, related_name='projects')
    Parent_Identifier = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='children')
    status = models.CharField(max_length=20, choices=[(status, status) for status in [Status.ACTIVATED, Status.DEACTIVATED]], default=Status.ACTIVATED)

    
    def __str__(self):
        return self.Project_name
    

        
class Accreditation(models.Model):
    CHOICES = (
    ('ALL_DESCENDANT', 'Tous les descendants du niveau'),
    ('LEVEL_ONLY', 'Niveau seulement'),
    )
    accreditation_identifier = StringUUIDField(primary_key=True, unique=True, default=uuid.uuid4, editable=False)
    status = models.CharField(max_length=20, choices=[(status, status) for status in [Status.ACTIVATED, Status.DEACTIVATED]], default=Status.ACTIVATED)
    projects_identifier = models.ForeignKey(Projects, on_delete=models.CASCADE)
    HieraItems_identifier=models.ForeignKey(HierarchyItem, on_delete=models.CASCADE)
    typeOfAccess=models.CharField(choices=CHOICES,  max_length=128)
    abstractuser = models.ForeignKey(Accounts, on_delete=models.CASCADE)
    assignedAt = models.DateTimeField(auto_now_add=True)
    lastUpdatedAt = models.DateTimeField(auto_now=True)
   # abstractGroup = models.ForeignKey(AccountGroup, on_delete=models.CASCADE)

      

























