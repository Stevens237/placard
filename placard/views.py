
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed,  ValidationError
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.core.mail import send_mail
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status, viewsets
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import AccountGroup
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
import jwt, datetime
from django.http import JsonResponse
from django.db import transaction
from rest_framework.generics import RetrieveUpdateDestroyAPIView
import uuid
from django.conf import settings
import re
from django.contrib.auth.hashers import make_password



from .models import  Autorisations, Role, Token, Accounts, AutorisationsGroup, Projects,  AccountGroup
from .models import Hierarchy, HierarchyItem, AccountGroup, Accounts, Accreditation, UsersGroupRelationship
from .serializers import  AutorisationSerializer, RoleSerializer, TokenSerializer,  AutorisationsGroupSerializer, AccountSerializer, GetAccountsSerializer
from .serializers import AccountsSerializer,  AccountGroupSerializer, ProjectSerializer, HierarchyItemSerializer, HierarchySerializer,UsersGroupAccountsSerializer
from . serializers import  AccountGroupCreateUsersSerializer,  GetRoleSerializer, AccountGroupDetailSerializer, UpdatedAccountGroupSerializer, UsersGroupRelationshipSerializer
Accounts = get_user_model()



# vue pour creer une accrediation 

class AddAccreditationView(APIView):
    def post(self, request, user_identifier):
        try:
            user = Accounts.objects.get(user_identifier=user_identifier)
        except Accounts.DoesNotExist:
            return Response({"message": "Utilisateur non trouvé"}, status=status.HTTP_404_NOT_FOUND)
        
        accreditation_data = request.data
        accreditations_info = []

        for accreditation_item_data in accreditation_data:
            action = accreditation_item_data.get('action')
            accreditation_info = {}

            if action == "ADD":
                projects_identifier = Projects.objects.get(pk=accreditation_item_data.get('projects_identifier'))
                hierarchy_item = HierarchyItem.objects.get(pk=accreditation_item_data.get('HieraItems_identifier'))

                # Vérifier si l'utilisateur n'a pas déjà cette accréditation
                existing_accreditation = Accreditation.objects.filter(
                    projects_identifier=projects_identifier,
                    HieraItems_identifier=hierarchy_item,
                    abstractuser=user
                ).exists()

                if not existing_accreditation:
                    accreditation = Accreditation.objects.create(
                        accreditation_identifier=str(uuid.uuid4()),
                        status='ACTIVATED',
                        projects_identifier=projects_identifier,
                        HieraItems_identifier=hierarchy_item,
                        typeOfAccess=accreditation_item_data.get('typeOfAccess'),
                        abstractuser=user,
                        
                        assignedAt=timezone.now(),
                        lastUpdatedAt=timezone.now()
                    )
                    assignedBy = user.user_identifier
                    accreditation_info['accreditation_identifier'] = accreditation.accreditation_identifier
                    accreditation_info['status'] = accreditation.status
                    accreditation_info['projects_identifier'] = accreditation.projects_identifier.pk
                    accreditation_info['HieraItems_identifier'] = accreditation.HieraItems_identifier.pk
                    accreditation_info['abstractuser'] = accreditation.abstractuser.pk
                    accreditation_info['typeOfAccess'] = accreditation.typeOfAccess
                    accreditation_info['assignedBy'] = assignedBy
                    accreditation_info['assignedAt'] = accreditation.assignedAt
                    accreditation_info['lastUpdatedAt'] = accreditation.lastUpdatedAt

                #else:
                    # Gérer le cas où l'utilisateur a déjà cette accréditation
                    #accreditation_info['message'] = "L'utilisateur a déjà cette accréditation"

            elif action == "REMOVE":
                try:
                    accreditation_to_remove = Accreditation.objects.filter(
                        projects_identifier=accreditation_item_data.get('projects_identifier'),
                        HieraItems_identifier=accreditation_item_data.get('HieraItems_identifier'),
                        abstractuser=user,
                        status='ACTIVATED'
                    ).first()

                    if accreditation_to_remove:
                        accreditation_to_remove.status = 'DEACTIVATED'
                        accreditation_to_remove.save()

                        removeBy = user.user_identifier
                        removeAt = timezone.now()

                        # Ajouter des informations pour l'action REMOVE
                        accreditation_info['accreditation_identifier'] = accreditation_to_remove.accreditation_identifier
                        accreditation_info['status'] = accreditation_to_remove.status
                        accreditation_info['projects_identifier'] = accreditation_to_remove.projects_identifier.pk
                        accreditation_info['HieraItems_identifier'] = accreditation_to_remove.HieraItems_identifier.pk
                        accreditation_info['abstractuser'] = accreditation_to_remove.abstractuser.pk
                        accreditation_info['typeOfAccess'] = accreditation_to_remove.typeOfAccess
                        accreditation_info['assignedAt'] = accreditation_to_remove.assignedAt
                        accreditation_info['lastUpdatedAt'] = accreditation_to_remove.lastUpdatedAt
                        accreditation_info['removeBy'] = removeBy
                        accreditation_info['removeAt'] = removeAt
                    else:
                        return Response({"message": "L'accréditation à supprimer n'existe pas"}, status=status.HTTP_404_NOT_FOUND)

                except ObjectDoesNotExist:
                    return Response({"message": "L'accréditation à supprimer n'existe pas"}, status=status.HTTP_404_NOT_FOUND)

            accreditations_info.append(accreditation_info)

        return Response(accreditations_info, status=status.HTTP_200_OK)



class AutorisationsGroupListCreateView(generics.ListCreateAPIView):
    queryset = AutorisationsGroup.objects.all()
    serializer_class = AutorisationsGroupSerializer

class AutorisationListCreateView(generics.ListCreateAPIView):
    queryset = Autorisations.objects.all()
    serializer_class = AutorisationSerializer



class AutorisationDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Autorisations.objects.all()
    serializer_class = AutorisationSerializer




# vue pour creer une Role
     
class RoleListCreateView(generics.CreateAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        autorisations_identifiers = data.pop('autorisations', [])  
        autorisations = Autorisations.objects.filter(autorisations_identifier__in=autorisations_identifiers)  

        role_name = data.get('display_name')
        user_id = request.user_id  # Récupérer l'identifiant de l'utilisateur à partir du JWT

        existing_role = Role.objects.filter(display_name=role_name).first()
        if existing_role:
            return Response({"error": "Role with this name already exists."}, status=status.HTTP_400_BAD_REQUEST)

        if not user_id:
            return Response({"error": "User identifier not found in JWT."}, status=status.HTTP_401_UNAUTHORIZED)

        user_accounts = get_object_or_404(Accounts, user_identifier=user_id)
        

        try:
            role_data = {
                'display_name': role_name,
                'createdBy': user_accounts,
                'lastUpdatedBy': user_accounts,
                'createdAt': timezone.now(),
                'lastUpdatedAt': timezone.now()
            }

            role = Role.objects.create(**role_data)
            role.autorisations.add(*autorisations)

            serialized_role = RoleSerializer(role)
            return Response(serialized_role.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




# vue pour la mise a jour du Nom d'un role  
class RoleUpdateView(RetrieveUpdateDestroyAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    lookup_field = 'role_identifier'

    def put(self, request, role_identifier):
        role = get_object_or_404(Role, role_identifier=role_identifier)
        
        display_name = request.data.get('display_name')

        # Vérifier si un autre rôle avec le même nom existe déjà
        existing_role = Role.objects.filter(display_name=display_name).exclude(role_identifier=role.role_identifier).first()
        if existing_role:
            return Response({"error": "Un rôle avec ce nom existe déjà."}, status=400)

        if display_name:
            role.display_name = display_name
            role.save()
            serializer = self.get_serializer(role)
            return Response(serializer.data)
        else:
            return Response({"error": "Missing display_name in request data."}, status=400)
    




# vue pour la mise a jour des autorisations d'un role




class UpdateRoleAutorisationsView(generics.UpdateAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    def update(self, request, *args, **kwargs):
        role_identifier = kwargs.get('role_identifier')
        autorisations_data = request.data  # Récupérer la liste complète des autorisations

        role = get_object_or_404(Role, role_identifier=role_identifier)

        autorisations_inexistantes = []

        for autorisation_data in autorisations_data:
            autorisations_identifier = autorisation_data.get('autorisations_identifier')
            action = autorisation_data.get('action')

            try:
                autorisation = Autorisations.objects.get(autorisations_identifier=autorisations_identifier)
            except Autorisations.DoesNotExist:
                # Ajouter l'identifiant de l'autorisation à la liste des autorisations inexistantes
                autorisations_inexistantes.append(autorisations_identifier)

        # Vérifier si des autorisations inexistantes ont été trouvées
        if autorisations_inexistantes:
            # Si oui, renvoyer un message d'erreur indiquant les autorisations inexistantes
            return Response({"error": f"The following authorizations does not exist: {', '.join(autorisations_inexistantes)}"}, status=status.HTTP_404_NOT_FOUND)

        # Si aucune autorisation inexistante n'a été trouvée, effectuer les opérations d'ajout ou de suppression d'autorisations
        for autorisation_data in autorisations_data:
            autorisations_identifier = autorisation_data.get('autorisations_identifier')
            action = autorisation_data.get('action')

            try:
                autorisation = Autorisations.objects.get(autorisations_identifier=autorisations_identifier)
            except Autorisations.DoesNotExist:
                # Cette partie du code ne devrait pas être atteinte car nous avons déjà vérifié les autorisations inexistantes
                pass

            if action == 'ADD' and autorisation not in role.autorisations.all():
                role.autorisations.add(autorisation)
            elif action == 'REMOVE' and autorisation in role.autorisations.all():
                role.autorisations.remove(autorisation)

        # Sauvegarder les modifications du rôle
        role.save()

        # Récupérer les données du rôle pour le retour
        serialized_role = RoleSerializer(role)

        return Response(serialized_role.data, status=status.HTTP_200_OK)




# vue pour desactiver un role
    
class RoleDeactivateView(RetrieveUpdateDestroyAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    lookup_field = 'role_identifier'

    def put(self, request, role_identifier, format=None):
        role = get_object_or_404(Role, role_identifier=role_identifier)

        # Désactiver le rôle
        role.status = 'Deactivated'
        role.save()

        serializer = self.get_serializer(role)
        return Response(serializer.data)
    





# vue pour activer un role    

class RoleActivateView(RetrieveUpdateDestroyAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    lookup_field = 'role_identifier'

    def put(self, request, role_identifier, format=None):
        role = get_object_or_404(Role, role_identifier=role_identifier)

        # Vérifier si le rôle est déjà activé
        if role.status == 'Activated':
            return Response({"message": "This Role is already Activated."}, status=400)

        # Activer le rôle
        role.status = 'Activated'
        role.save()

        serializer = self.get_serializer(role)
        return Response(serializer.data)





# vue pour afficher la liste des  roles

class RoleListView(generics.ListAPIView):
    queryset = Role.objects.all()
    serializer_class = GetRoleSerializer






# vue pour avoir les details sur un role bien precis  

class RoleDetailView(generics.RetrieveUpdateDestroyAPIView):
    lookup_url_kwarg = 'role_identifier'
    serializer_class = AccountGroupSerializer  

    def get(self, request, role_identifier):
        role_detail = get_object_or_404(Role, role_identifier=role_identifier)
        serializer = RoleSerializer(role_detail)
        return Response(serializer.data)
    queryset = Role.objects.all()  # Définir le queryset pour la vue
    serializer_class = RoleSerializer





# vue qui permet d'ajouter un role à un Utilisateur ou bien  à un  groupe d'utilisateur 
    
"""class AssignRolesView(generics.UpdateAPIView):
    def update(self, request, *args, **kwargs):
        user_identifier = kwargs.get('user_identifier')
        group_identifier = kwargs.get('group_identifier')
        roles_data = request.data.get('roles', [])

        if user_identifier:
            user = get_object_or_404(Accounts, user_identifier=user_identifier)
            user.roles.set(roles_data)
            return Response({"message": "Roles assigned to the user successfully."}, status=status.HTTP_200_OK)
        elif group_identifier:
            group = get_object_or_404(AccountGroup, group_identifier=group_identifier)
            for accounts in group.accounts.all():
                accounts.roles.set(roles_data)
            return Response({"message": "Roles assigned to all users in the group successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User or group identifier not provided."}, status=status.HTTP_400_BAD_REQUEST)"""





class AssignRolesView(generics.UpdateAPIView):
    def update(self, request, *args, **kwargs):
        user_identifier = kwargs.get('user_identifier')
        group_identifier = kwargs.get('group_identifier')
        roles_data = request.data.get('roles', [])
        #roles_data = request.data.get('group_roles', [])
        
        missing_roles = []

        if user_identifier:
            user = get_object_or_404(Accounts, user_identifier=user_identifier)
            for role_data in roles_data:
                role_identifier = role_data.get('role_identifier')
                action = role_data.get('action')

                try:
                    role_uuid = uuid.UUID(role_identifier)
                    role = Role.objects.get(role_identifier=role_uuid)
                except (ValueError, Role.DoesNotExist):
                    missing_roles.append(role_identifier)

            if missing_roles:
                return Response({"error": f"Roles with identifiers {missing_roles} do not exist"}, status=status.HTTP_404_NOT_FOUND)
            
            for role_data in roles_data:
                role_identifier = role_data.get('role_identifier')
                action = role_data.get('action')
                role_uuid = uuid.UUID(role_identifier)
                role = Role.objects.get(role_identifier=role_uuid)

                if action == 'ADD':
                    user.roles.add(role)
                elif action == 'REMOVE':
                    user.roles.remove(role)

            serializer = AccountsSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        elif group_identifier: 
            group = get_object_or_404(AccountGroup, group_identifier=group_identifier)
            for role_data in roles_data:
                role_identifier = role_data.get('role_identifier')
                action = role_data.get('action')

                try:
                    role_uuid = uuid.UUID(role_identifier)
                    role = Role.objects.get(role_identifier=role_uuid)
                except (ValueError, Role.DoesNotExist):
                    missing_roles.append(role_identifier)

                if action == 'ADD':
                    group.roles.add(role)
                elif action == 'REMOVE':
                    group.roles.remove(role)

            if missing_roles:
                return Response({"error": f"Roles with identifiers {missing_roles} do not exist"}, status=status.HTTP_404_NOT_FOUND)
            
            for accounts in group.accounts.all():
                for role_data in roles_data:
                    role_identifier = role_data.get('role_identifier')
                    action = role_data.get('action')
                    role_uuid = uuid.UUID(role_identifier)
                    roles = Role.objects.get(role_identifier=role_uuid)

                    if action == 'ADD':
                        accounts.roles.add(roles)
                    elif action == 'REMOVE':
                        accounts.roles.remove(roles)

            serializer = AccountGroupSerializer(group)
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response({"error": "User or group identifier not provided."}, status=status.HTTP_400_BAD_REQUEST)

class AssignUsersToGroup(generics.UpdateAPIView):
    serializer_class = UpdatedAccountGroupSerializer

    def update(self, request, *args, **kwargs):
        # Récupérer l'identifiant de l'utilisateur à partir du JWT
        user_id = request.user_id 
        
        group_identifier = kwargs.get('group_identifier')
        account_group = get_object_or_404(AccountGroup, group_identifier=group_identifier)

        data = request.data
        accounts_data = data.get('accounts', [])
        

        for account_data in accounts_data:
            user_identifier = account_data.get('user_identifier')
            action = account_data.get('action')

            if action == 'ADD':
                try:
                    user_account = get_object_or_404(Accounts, user_identifier=user_id)
                    
                    relationship, created = UsersGroupRelationship.objects.get_or_create(account_identifier=user_account, accounts_group_identifier=account_group)

                    if not created:
                        if relationship.statut_in_Group == 'deactivated':
                            relationship.statut_in_Group = 'activated'
                            relationship.save()
                        else:
                            return Response({"error": f"User with user identifier '{user_id}' is already in the group"}, status=status.HTTP_400_BAD_REQUEST)
                    else:
                      
                        relationship.statut_in_Group = 'activated'
                        relationship.createdBy = user_account  
                        relationship.lastUpdatedBy = user_account 
                        relationship.save()
                except IntegrityError:
                    return Response({"error": f"User with user identifier '{user_id}' is already in the group"}, status=status.HTTP_400_BAD_REQUEST)
                except Accounts.DoesNotExist:
                    return Response({"error": f"User with user identifier '{user_id}' does not exist"}, status=status.HTTP_400_BAD_REQUEST)

            elif action == 'REMOVE':
                try:
                    user_account = get_object_or_404(Accounts, user_identifier=user_id)
                    relationship = UsersGroupRelationship.objects.get(account_identifier=user_account, accounts_group_identifier=account_group)
                    if relationship.statut_in_Group == 'activated':
                        relationship.statut_in_Group = 'deactivated'
                        relationship.lastUpdatedBy = user_account  
                        relationship.save()
                    else:
                        return Response({"error": f"User with user identifier '{user_id}' is not in the group"}, status=status.HTTP_400_BAD_REQUEST)
                except UsersGroupRelationship.DoesNotExist:
                    return Response({"error": f"User with user identifier '{user_id}' is not in the group"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UpdatedAccountGroupSerializer(instance=account_group)
        return Response(serializer.data, status=status.HTTP_200_OK)


                    


class TokenListCreateView(generics.ListCreateAPIView):
    queryset = Token.objects.all()
    serializer_class = TokenSerializer




class TokenDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Token.objects.all()
    serializer_class = TokenSerializer

# vue pour creer un utilisateur 
    
class AccountsListCreateView(generics.ListCreateAPIView):
    queryset = Accounts.objects.all()
    serializer_class = AccountsSerializer

    def perform_create(self, serializer):
        data = self.request.data
        accounts = Accounts.objects.create_accounts(email=data['email'], first_name=data['first_name'], last_name=data['last_name'])
        accounts.save()
       # Token.create_token_for_user(user)
        
class GetAccountsListCreateView(generics.ListCreateAPIView):
    queryset = Accounts.objects.all()
    serializer_class = GetAccountsSerializer

    def perform_create(self, serializer):
        data = self.request.data
        accounts = Accounts.objects.create_accounts(email=data['email'], first_name=data['first_name'], last_name=data['last_name'])
        accounts.save()
       # Token.create_token_for_user(user)
            
class AccountsDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Accounts.objects.all()
    serializer_class = AccountsSerializer
   
# vue pour creer un groupe d'utilisateur 
       
class AccountGroupListCreateView(APIView):
   
    # veritable vue pour la recuperaion des groupe
    def get(self, request, group_identifier=None):
        
        if group_identifier is not None:
            account_group = get_object_or_404(AccountGroup, group_identifier=group_identifier)

            data = {
                'display_name': account_group.display_name,
                'group_identifier': account_group.group_identifier,
                'status ': account_group.status,
                'createdAt': account_group.created_at,
                'last_updated_at': account_group.last_updated_at 

            }
            return Response(data, status=status.HTTP_200_OK)
        else:
            account_groups = AccountGroup.objects.all()
            data = [{'group_identifier': group.group_identifier,  'display_name': group.display_name, 'status': group.status, 'createdAt': group.created_at,
                      'last_updated_at':group.last_updated_at  } for group in account_groups]
            #data =[{'display_name':group.display_name} for group in account_groups]
            return Response(data, status=status.HTTP_200_OK)
        
  
# cette vue permet de supprimer  les  noms des groupes d'utilisateur
    
    
    def put(self, request, group_identifier):
            account_group = get_object_or_404(AccountGroup, group_identifier=group_identifier)
            serializer = AccountGroupSerializer(account_group, data=request.data)
            if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    def post(self, request):
            data = request.data.copy()
            emails = data.pop('accounts', [])

            accounts = []
            for email in emails:
                user = get_object_or_404(Accounts, email=email)
                accounts.append(user)

            data['accounts'] = accounts

            serializer = AccountGroupSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class AccountGroupDetailView(generics.RetrieveUpdateDestroyAPIView):
    lookup_url_kwarg = 'group_identifier'
    serializer_class = AccountGroupDetailSerializer
    queryset = AccountGroup.objects.all()

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()

        # Exclure le champ 'roles' des données de requête pour empêcher sa mise à jour
        if 'roles' in request.data:
            del request.data['roles']

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        
        # Ignorer explicitement la mise à jour du champ 'roles'
        if 'roles' in serializer.validated_data:
            del serializer.validated_data['roles']

        self.perform_update(serializer)

        return Response(serializer.data)


    # Vue qui permet d'extraire et afficher les utilisteurs dans un Groupe en fonction de l'identifiant du Groupe


class AccountGroupAllAccountsView(generics.ListAPIView):

    serializer_class = AccountSerializer

    def get_queryset(self):
        group_identifier = self.kwargs['group_identifier']
        account_group = get_object_or_404(AccountGroup, group_identifier=group_identifier)
        return account_group.accounts.all()
    
     # Vue qui permet d'extraire et afficher les Role dans un Groupe en fonction de l'identifiant du Groupe
    


class AccountGroupAllRoleView(generics.ListAPIView):
    serializer_class = RoleSerializer

    def list(self, request, *args, **kwargs):
        group_identifier = self.kwargs['group_identifier']
        account_group = get_object_or_404(AccountGroup, group_identifier=group_identifier)
        
        roles_data = []
        for role in account_group.roles.all():
            role_data = {
                'role_identifier': role.role_identifier,
                'display_name': role.display_name,
                'autorisations': list(role.autorisations.values_list('autorisations_identifier', flat=True))
            }
            roles_data.append(role_data)
        
        return Response(roles_data)
     
     # Vue qui permet d'extraire et afficher les Accreditations dans un Groupe en fonction de l'identifiant du Groupe
    

    
    #class Role(models.Model):
   # display_name = models.CharField(max_length=255)
    #autorisations = models.ManyToManyField(Autorisation, related_name='roles')
    #role_identifier= models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)


   
class ProjectListCreateView(generics.ListCreateAPIView):
    queryset=Projects.objects.all()
    serializer_class = ProjectSerializer



class ProjectsCreateView(generics.CreateAPIView):
    queryset = Projects.objects.all()
    serializer_class = ProjectSerializer

    def post(self, request, *args, **kwargs):

        data = request.data.copy()
        
        parent_identifier = data.get('Parent_Identifier')
        
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
    

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)



class ProjectDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Projects.objects.all()
    serializer_class = ProjectSerializer
    lookup_field = 'Project_identifier'  # champ correct pour l'identifiant

    def put(self, request, Project_identifier):  # Utiliser le même nom de champ dans la méthode put
        project_item = get_object_or_404(Projects, Project_identifier=Project_identifier)  # Utiliser le même nom de champ ici
        serializer = self.get_serializer(project_item, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

  # Vue qui permet a un utilisateur de se connecter 
    


class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        accounts = Accounts.objects.filter(email=email).first()

        if accounts is None:
            raise AuthenticationFailed('Incorrect Username or Password!')

        if not accounts.check_password(password):
            raise AuthenticationFailed('Incorrect Username or Password!')
        payload = {
            'id': str(accounts.user_identifier),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=600),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }
        return response




class AccountsView(APIView):

    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithm=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        accounts = Accounts.objects.filter(id=payload['id']).first()
        serializer = AccountsSerializer(accounts)
        return Response(serializer.data)


#vue qui permet de donner les details d'informations sur un utilisateur 
    
class UserDetailsView(generics.RetrieveAPIView):
    queryset = Accounts.objects.all()
    serializer_class = GetAccountsSerializer

    def retrieve(self, request, *args, **kwargs):
        user_identifier = kwargs.get('user_identifier')
        user = get_object_or_404(Accounts, user_identifier=user_identifier)
        serializer = GetAccountsSerializer(user)
        return Response(serializer.data)


# vue qui permet de modifier un utilisateur en fonction du user_identifier

class UpdateUserView(generics.UpdateAPIView):
    queryset = Accounts.objects.all()
    serializer_class = AccountsSerializer

    def update(self, request, *args, **kwargs):
        user_identifier = kwargs.get('user_identifier')
        user = get_object_or_404(Accounts, user_identifier=user_identifier)

        # Exclure le champ 'role' des données de la requête
        if 'roles' in request.data:
            del request.data['roles']

        serializer = GetAccountsSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LogoutView(APIView):
    def post(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            # Vérifier la validité du token
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            # Le token a expiré, peut-être vous souhaitez gérer cela différemment
            raise AuthenticationFailed('Token has expired')

        # Procéder à la déconnexion uniquement si le token est valide
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'succesful deconnexion'
        }
        return response




class PasswordResetTokenGenerator(PasswordResetTokenGenerator):
    expires = 3600  # Durée en secondes de vie d'un token 

    def _make_hash_value(self, accounts, timestamp):
        return (
            smart_str(accounts.pk) + smart_str(timestamp) +
            smart_str(accounts.is_active)
        )

    def _check_token_expiration(self, accounts, timestamp):
        if self.expires is None:
            return False
        return timezone.now() <= timestamp + timedelta(seconds=self.expires)




class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email', None)
        accounts = Accounts.objects.filter(email=email).first()

        if accounts:
            # Génération du jeton de réinitialisation sans envoi d'e-mail
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(accounts)
            
            # Obtention de l'UID de l'utilisateur
            uidb64 = urlsafe_base64_encode(force_bytes(accounts.pk))
            
            # Construction de l'URL de réinitialisation
            reset_url = f"http://127.0.0.1:8000/password/reset/{uidb64}/{token}/"
            
            print(f"Reset URL: {reset_url}")
            
            return Response({'token': token, 'reset_url': reset_url}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)



class PasswordDefineView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            accounts = Accounts.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, Accounts.DoesNotExist, DjangoUnicodeDecodeError):
            accounts = None

        if accounts:
            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(accounts, token):
                print(f"Token checked at: {timezone.now()}")
                return Response({'detail': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

            password = request.data.get('password', None)
            
            # Vérifier la longueur minimale du mot de passe
            if len(password) < 8:
                return Response({'detail': 'Le mot de passe doit contenir au moins 8 caractères.'}, status=status.HTTP_400_BAD_REQUEST)

            # Vérification des critères de complexité du mot de passe
            criteria = {
                'lowercase': False,
                'uppercase': False,
                'digit': False,
                'special_char': False
            }

            for char in password:
                if char.islower():
                    criteria['lowercase'] = True
                elif char.isupper():
                    criteria['uppercase'] = True
                elif char.isdigit():
                    criteria['digit'] = True
                elif not char.isalnum():
                    criteria['special_char'] = True

            if not any(criteria.values()):
                # Aucun critère n'est satisfait
                return Response({'detail': 'Le mot de passe doit contenir au moins une lettre majuscule, une lettre minuscule, un chiffre et un caractère spécial.'}, status=status.HTTP_400_BAD_REQUEST)
            
            accounts.set_password(password)
            accounts.save()

            print(f"Password updated for user {accounts.username} at: {timezone.now()}")

            return Response({'detail': 'Le mot de passe a été défini avec succès.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)
            










"""
    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            accounts = Accounts.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, Accounts.DoesNotExist, DjangoUnicodeDecodeError):
            accounts = None

        if accounts:
            # Utilisation de la propriété expires lors de la vérification du jeton
            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(accounts, token):
                print(f"Token checked at: {timezone.now()}")
                return Response({'detail': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

            # ...
            print(f"Attempting to define password for user {accounts.username}")

            # si le token est valide , enregistrer le nouveau mot de passe
            password = request.data.get('password', None)
            accounts.set_password(password)
            accounts.save()

            #  ligne de journalisation pour vérifier si le mot de passe est réellement mis à jour
            print(f"Password updated for user {accounts.username} at: {timezone.now()}")



            return Response({'detail': 'Password has been Define successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)"""
        




class PasswordResetView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            accounts = Accounts.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, Accounts.DoesNotExist):
            accounts = None

        if accounts:
            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(accounts, token):
                print(f"Token checked at: {timezone.now()}")
                return Response({'detail': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

            password = request.data.get('password', None)
            
            # Vérifier la longueur minimale du mot de passe
            if len(password) < 8:
                return Response({'detail': 'Le mot de passe doit contenir au moins 8 caractères.'}, status=status.HTTP_400_BAD_REQUEST)

            # Vérification des critères de complexité du mot de passe
            criteria = {
                'lowercase': False,
                'uppercase': False,
                'digit': False,
                'special_char': False
            }

            for char in password:
                if char.islower():
                    criteria['lowercase'] = True
                elif char.isupper():
                    criteria['uppercase'] = True
                elif char.isdigit():
                    criteria['digit'] = True
                elif not char.isalnum():
                    criteria['special_char'] = True

            if not any(criteria.values()):
                # Certains critères ne sont pas satisfaits
                return Response({'detail': 'Le mot de passe doit contenir au moins une lettre majuscule, une lettre minuscule, un chiffre et un caractère spécial.'}, status=status.HTTP_400_BAD_REQUEST)

            # Mettre à jour le mot de passe avec le nouveau mot de passe haché
            accounts.password = make_password(password)
            accounts.save()

            print(f"Password updated for user {accounts.username} at: {timezone.now()}")

            return Response({'detail': 'Le mot de passe a été réinitialisé avec succès.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)



"""class ChangePasswordView(APIView):

    permission_classes = [IsAuthenticated]

    def put(self, request):
        accounts = request.accounts

        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        # verification of old password 
        if not accounts.check_password(old_password):
            return Response({'message': 'mot de passe incorrect'}, status=status.HTTP_400_BAD_REQUEST)

        # check if the new password and the confirmation password is the same 
        if new_password != confirm_password:
            return Response({'message': 'Les  mots de passe ne correspondent pas'}, status=status.HTTP_400_BAD_REQUEST)

        # Change the password 
        accounts.set_password(new_password)
        accounts.save()

        return Response({'message': 'Mot de passe modifié avec succès'}, status=status.HTTP_200_OK)"""


class ChangePasswordView(APIView):

    
    permission_classes = [IsAuthenticated]

    def put(self, request):
        accounts = request.accounts

        # Vérifier si les champs actuel, nouveau et confirmation du mot de passe sont fournis
        current_password = request.data.get('current_password', None)
        new_password = request.data.get('new_password', None)
        confirm_new_password = request.data.get('confirm_new_password', None)

        if not all([current_password, new_password, confirm_new_password]):
            return Response({'detail': 'Veuillez fournir votre mot de passe actuel, le nouveau mot de passe et la confirmation du nouveau mot de passe.'}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier si le nouveau mot de passe correspond à la confirmation
        if new_password != confirm_new_password:
            return Response({'detail': 'Le nouveau mot de passe et la confirmation du mot de passe ne correspondent pas.'}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier si le mot de passe actuel est correct
        if not accounts.check_password(current_password):
            return Response({'detail': 'Le mot de passe actuel est incorrect.'}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier la longueur minimale du nouveau mot de passe
        if len(new_password) < 8:
            return Response({'detail': 'Le nouveau mot de passe doit contenir au moins 8 caractères.'}, status=status.HTTP_400_BAD_REQUEST)

        # Vérification des critères de complexité du nouveau mot de passe
        criteria = {
            'lowercase': False,
            'uppercase': False,
            'digit': False,
            'special_char': False
        }

        for char in new_password:
            if char.islower():
                criteria['lowercase'] = True
            elif char.isupper():
                criteria['uppercase'] = True
            elif char.isdigit():
                criteria['digit'] = True
            elif not char.isalnum():
                criteria['special_char'] = True

        if not all(criteria.values()):
            # Certains critères ne sont pas satisfaits
            return Response({'detail': 'Le nouveau mot de passe doit contenir au moins une lettre majuscule, une lettre minuscule, un chiffre et un caractère spécial.'}, status=status.HTTP_400_BAD_REQUEST)

        # Mettre à jour le mot de passe avec le nouveau mot de passe haché
        accounts.password = make_password(new_password)
        accounts.save()

        print(f"Password updated for user {accounts.username} at: {timezone.now()}")

        return Response({'detail': 'Le mot de passe a été modifié avec succès.'}, status=status.HTTP_200_OK)



class PasswordDefineRequestView(APIView):

    def post(self, request):
        email = request.data.get('email', None)
        accounts = Accounts.objects.filter(email=email).first()

        if accounts:
            # Génération du jeton de réinitialisation sans envoi d'e-mail
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(accounts)
            
            # Obtention de l'UID de l'utilisateur
            uidb64 = urlsafe_base64_encode(force_bytes(accounts.pk))
            
            # Construction de l'URL de réinitialisation
            define_url = f"http://127.0.0.1:8000/password/define/{uidb64}/{token}/"
            
            print(f"Define URL: {define_url}")
            
            return Response({'token': token, 'define_url': define_url}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        



class HierarchyListCreateView(generics.ListCreateAPIView):
    queryset = Hierarchy.objects.all()
    serializer_class = HierarchySerializer



class HierarchyDetailView(RetrieveUpdateDestroyAPIView):
   
    queryset = Hierarchy.objects.all()
    serializer_class = HierarchySerializer
    lookup_field = 'hierachy_identifier'  

    def put(self, request, hierachy_identifier): 
        hierarchy_item = get_object_or_404(Hierarchy, hierachy_identifier=hierachy_identifier) 
        serializer = self.get_serializer(hierarchy_item, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)




class HierarchyItemDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = HierarchyItem.objects.all()
    serializer_class = HierarchyItemSerializer
    lookup_field = 'HieraItem_identifier' 

    def put(self, request, HieraItem_identifier):  
        hierarchy_items = get_object_or_404(HierarchyItem, HieraItem_identifier=HieraItem_identifier)  
        serializer = self.get_serializer(hierarchy_items, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)



class AccountGroupAccountsView(APIView):
    
    def get(self, request, group_identifier=None):
        
        if group_identifier is not None:
            account_group = get_object_or_404(AccountGroup, group_identifier=group_identifier)
            accounts = account_group.accounts.all()  # Assuming 'accounts' is the related name in AccountGroup model


            serializer = AccountSerializer(accounts, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Group identifier not provided"}, status=status.HTTP_400_BAD_REQUEST)
       

class AccountGroupPersonalAccountsView(APIView):
    
    def get(self, request, group_identifier=None, identifier=None,):
        
        if group_identifier is not None and identifier is not None:
            account_group = get_object_or_404(AccountGroup, group_identifier=group_identifier)
            account = get_object_or_404(Accounts, identifier=identifier, account_group=account_group)

            data = {
                'first_name': account.first_name,
                'last_name': account.last_name,
                'email': account.email,
                'roles': account.roles,  # Assuming roles is a field in your Accounts model
                'identifier': account.identifier,
                'group_identifier': account_group.group_identifier
            }

            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Group identifier or Account identifier not provided"}, status=status.HTTP_400_BAD_REQUEST)
        
 # vue qui permet d'ajouter un utilisateur dans un groupe      


class AccountGroupAddAccountsView(APIView):
    
    def post(self, request, group_identifier):
        account_group = get_object_or_404(AccountGroup, group_identifier=group_identifier)

        data = request.data
        user_identifiers = data.get('accounts', [])

        for user_identifier in user_identifiers:
            if not Accounts.objects.filter(user_identifier=user_identifier).exists():
                return Response({"error": f"User with user identifier '{user_identifier}' Does not exist"}, status=status.HTTP_400_BAD_REQUEST)
            
            if account_group.accounts.filter(user_identifier=user_identifier).exists():
                return Response({"error": f"User with user identifier '{user_identifier}' is already in the group"}, status=status.HTTP_400_BAD_REQUEST)
            
            account = Accounts.objects.get(user_identifier=user_identifier)
            account_group.accounts.add(account)

        serializer = AccountGroupCreateUsersSerializer(instance=account_group)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class AccountGroupDeleteAccountsView(RetrieveUpdateDestroyAPIView):
    queryset = AccountGroup.objects.all()
    lookup_field = 'group_identifier'
    serializer_class = AccountGroupCreateUsersSerializer

    def delete(self, request, group_identifier):
        account_group = get_object_or_404(AccountGroup, group_identifier=group_identifier)

        data = request.data
        user_identifiers = data.get('accounts', [])

        for user_identifier in user_identifiers:
            try:
                account = Accounts.objects.get(user_identifier=user_identifier)
                account_group.accounts.remove(account)
            except Accounts.DoesNotExist:
                return Response({"error": f"User with user identifier '{user_identifier}' does not exist"}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(account_group)
        return Response(serializer.data, status=status.HTTP_200_OK)
    


class HierarchyItemCreateView(generics.CreateAPIView):

    queryset = HierarchyItem.objects.all()
    serializer_class = HierarchyItemSerializer
    
    def post(self, request, *args, **kwargs):
        data = request.data.copy()
        level = data.get('level')
        parent_identifier = data.get('parent_identifier')

        

        if level == 1 and parent_identifier is not None:
            return Response({"error": "Un élément de niveau 1 ne peut pas avoir de parent."}, status=status.HTTP_400_BAD_REQUEST)
        
        if level > 1 and (not parent_identifier or parent_identifier.strip() == ''):

            return Response({"error": "Un élément de niveau supérieur à 1 doit avoir un parent."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
   
    
        
    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)































"""def post(self, request, *args, **kwargs):
        data = request.data.copy()

        if data.get('level') == 1:
            data['parent_identifier'] = None

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)"""




# mise a jour d'un role 
        
"""class RoleUpdateView(generics.UpdateAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    def put(self, request, *args, **kwargs):
        role_identifier = kwargs.get('role_identifier')
        data = request.data

        # Vérifier si 'display_name' est présent dans les données
        display_name = data.get('display_name')
        if not display_name:
            return Response({"error": "'display_name' is required for role update."}, status=status.HTTP_400_BAD_REQUEST)

        role = get_object_or_404(Role, role_identifier=role_identifier)

        existing_role = Role.objects.exclude(role_identifier=role_identifier).filter(display_name=display_name).first()
        if existing_role:
            return Response({"error": "Role with this name already exists."}, status=status.HTTP_400_BAD_REQUEST)

        # Mettre à jour les champs du rôle
        role.display_name = display_name
        role.lastUpdatedAt = timezone.now()
        #role.lastUpdatedBy = request.user.user_identifier  # Utilisateur ayant initié la requête

        # Mettre à jour les autorisations du rôle
        autorisations = data.get('autorisations', [])
        role.autorisations.clear()  # Supprimer les anciennes autorisations
        for autorisation in autorisations:
            role.autorisations.add(autorisation)

        # Enregistrer les modifications
        role.save()

        serialized_role = RoleSerializer(role)
        return Response(serialized_role.data, status=status.HTTP_200_OK)"""



class HierarchyCopyView(generics.CreateAPIView):
    queryset = Hierarchy.objects.all()
    serializer_class = HierarchySerializer

    def create(self, request, *args, **kwargs):
       
        hierarchy_identifier = request.data.get('hierarchy_identifier')
       
        new_name = request.data.get('new_name')

        
        hierarchy_to_copy = get_object_or_404(Hierarchy, hierarchy_identifier=hierarchy_identifier)

        # Créer une nouvelle hiérarchie avec le nouveau nom
        new_hierarchy_data = {
            'name': new_name,
            
        }
        new_hierarchy_serializer = HierarchySerializer(data=new_hierarchy_data)
        if new_hierarchy_serializer.is_valid():
            new_hierarchy_serializer.save()
            return Response(new_hierarchy_serializer.data, status=status.HTTP_201_CREATED)