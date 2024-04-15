from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from .models import AutorisationsGroup, Autorisations, Role, Token, Accounts, AccountGroup, Projects
from .models import Hierarchy, HierarchyItem,Accreditation,UsersGroupRelationship

User = get_user_model()

class AutorisationsGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = AutorisationsGroup
        fields = '__all__'



class AutorisationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Autorisations
        fields = ['display_name','autorisations_identifier']



class RoleSerializer(serializers.ModelSerializer):
    autorisations = serializers.SlugRelatedField(slug_field='autorisations_identifier', queryset=Autorisations.objects.all(), many=True)
    #createdBy = serializers.CharField(source='createdBy.username', read_only=True)
    #lastUpdatedBy = serializers.CharField(source='lastUpdatedBy.username', read_only=True)
    createdAt = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    lastUpdatedAt = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    class Meta:
        model = Role
        fields = ['display_name','autorisations', 'role_identifier', 'status', 'createdBy','lastUpdatedBy', 'createdAt', 'lastUpdatedAt']



class GetRoleSerializer(serializers.ModelSerializer):
    #autorisations = serializers.SlugRelatedField(slug_field='identifier', queryset=Autorisations.objects.all(), many=True)
    class Meta:
        model = Role
        fields = ['display_name', 'role_identifier', 'status', 'createdBy', 'createdAt']
 


class TokenSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Token
        fields = '__all__'



class GetAccountsSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Accounts
      
        fields = ['user_identifier', 'first_name', 'last_name', 'email', 'roles', 'status', 'accreditations']


class AccountsSerializer(serializers.ModelSerializer):
    # Ajouter un champ email à votre sérialiseur
    email = serializers.EmailField()

    class Meta:
        model = Accounts
        fields = ['email', 'first_name', 'last_name']

    def validate_email(self, value):
        # Vérifier si un objet avec le même e-mail existe déjà
        existing_accounts = Accounts.objects.filter(email=value).first()
        if existing_accounts:
            # Si un objet avec le même e-mail existe déjà, lever une exception de validation
            raise serializers.ValidationError("Un compte avec cet e-mail existe déjà")
        return value




class AccountGroupSerializer(serializers.ModelSerializer):
   # accounts = serializers.SlugRelatedField(slug_field='email', queryset=Accounts.objects.all(), many=True)
    #created_by = serializers.ReadOnlyField(source='created_by_id') 

    class Meta:
        model = AccountGroup
        fields = ['group_identifier', 'display_name', 'status', 'last_updated_at', 'roles',  'accreditations']

    def validate(self, data):
        display_name = data.get('display_name')
        
        if AccountGroup.objects.filter(display_name=display_name).exists():
            raise serializers.ValidationError("A group with the same Name already exists.")
        
        return data




class AccountGroupDetailSerializer(serializers.ModelSerializer):
    class Meta:
            model = AccountGroup
            fields = ['group_identifier', 'display_name', 'status', 'last_updated_at', 'roles',   'accreditations']

    def validate(self, data):
            display_name = data.get('display_name')
            
            if AccountGroup.objects.filter(display_name=display_name).exists():
                raise serializers.ValidationError("A group with the same Name already exists.")
            
            return data




class AccountGroupCreateUsersSerializer(serializers.ModelSerializer):
    accounts = serializers.SerializerMethodField()
    class Meta:
        model = AccountGroup
        fields = [  'group_identifier','display_name','status', 'accounts',  'created_at', 'date_joined']

       #  méthode get_accounts qui sera utilisée pour obtenir les données des comptes associés à l'instance du groupe de comptes. 

    def get_accounts(self, instance):
       
        accounts_data = []
        for user_identifier in instance.accounts.values_list('user_identifier', flat=True):
            user = get_user_model().objects.filter(user_identifier=user_identifier).first()
            if user:
                account_data = {
                    'user_identifier': str(user.user_identifier),
                    'email': user.email,
                    'status':user.status,
                }
                accounts_data = [account_data]  # Réinitialisation de la liste avec le compte actuel
            break  # Sortir de la boucle après avoir ajouté le compte
        return accounts_data
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['accounts'] = self.get_accounts(instance)
        return data
    







class UsersGroupAccountsSerializer(serializers.ModelSerializer):
    accounts = serializers.SerializerMethodField()

    class Meta:
        model = UsersGroupRelationship
        fields = [ 'accounts', 'statut_in_Group', 'added_at', 'last_updated_at', 'added_by', 'last_updated_by']

    def get_accounts(self, instance):
        accounts_data = []
        
        user_accounts = instance.user_identifier.all() 
        for account in user_accounts:
            account_data = {
                'user_identifier': str(instance.user_identifier),
                'email': account.email,
                'status': account.status,
            }
            accounts_data.append(account_data)
        return accounts_data

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['accounts'] = self.get_accounts(instance)
        return data












class UpdatedAccountGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccountGroup
        fields = [  'group_identifier','display_name','status', 'accounts',  'created_at']









class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Projects
        fields = ['Project_identifier', 'Project_name', 'hierachy_identifier', 'Parent_Identifier', 'status']

    def validate(self, data):
        parent_identifier = data.get('Parent_Identifier')
        Project_name = data.get('Project_name')

        if parent_identifier:
            if parent_identifier.Project_name == Project_name:
                raise serializers.ValidationError("Projects child and parent cannot have the same name.")
        




        if Projects.objects.filter(Project_name=Project_name).exists():
            raise serializers.ValidationError("An item with the same name already exists.")

        return data





class HierarchyItemSerializer(serializers.ModelSerializer):
    

    class Meta:
        model = HierarchyItem
        fields = ['HieraItem_identifier', 'hierarchy_identifier', 'name', 'level', 'parent_identifier', 'status']

    def validate(self, data):
        parent = data.get('parent_identifier')
        level = data.get('level')
        name = data.get('name')
        print(data.get('hierarchy_identifier'))
        if parent:
                if parent.level >= int(level):
                    raise serializers.ValidationError("Child level should be greater than the parent level.")

                if parent.name == name:
                    raise serializers.ValidationError("The child and parent cannot have the same name.")
                     

        if HierarchyItem.objects.filter(name=name).exists():
            raise serializers.ValidationError("An item with the same name already exists.")

        return data










class AccountPersonalSerializer(serializers.ModelSerializer):

    account_group = AccountGroupSerializer()

    class Meta:
        model = Accounts
        fields = ['account_group', 'first_name', 'last_name', 'email', 'identifier']




# Serializer pour le modèle Hierarchy  
class HierarchySerializer(serializers.ModelSerializer):
    class Meta:
        model = Hierarchy
        fields = ['hierachy_identifier', 'hierarchy_name', 'status']

    def validate_hierarchy_name(self, value):
        if self.instance and self.instance.hierarchy_name == value:
            return value

        if Hierarchy.objects.filter(hierarchy_name=value).exists():
            raise serializers.ValidationError(" The hierarchy with this name is  already exists. ")
        
        return value



class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model=Accounts
        fields = ['user_identifier', 'email', 'first_name', 'last_name', 'status', 'created_at']




class AccreditationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Accreditation
        fields = ['accreditation_identifier',   'status', 'projects_identifier']



class UsersGroupRelationshipSerializer(serializers.ModelSerializer):
    user_identifier = serializers.CharField(source='account.user_identifier', read_only=True)
    user_email = serializers.CharField(source='account.email', read_only=True)
    user_first_name = serializers.CharField(source='account.first_name', read_only=True)
    user_last_name = serializers.CharField(source='account.last_name', read_only=True)
    user_status = serializers.CharField(source='account.status', read_only=True)

    class Meta:
        model = UsersGroupRelationship
        fields = ['user_identifier', 'user_email', 'user_first_name', 'user_last_name', 'user_status', 'statut_in_Group', 'createdBy', 'lastUpdatedBy', 'createdAt', 'lastUpdatedAt']

class UpdatedAccountGroupSerializer(serializers.ModelSerializer):
    users_group_relationship = UsersGroupRelationshipSerializer(many=True, read_only=True)

    class Meta:
        model = AccountGroup
        fields = ['group_identifier', 'display_name', 'status', 'accounts', 'created_at', 'users_group_relationship']














#commande de gestion de Django utilisée via la ligne de commande pour charger des données à partir de fichiers dans la base de données.
        