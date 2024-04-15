from django.urls import path

from .views import AutorisationsGroupListCreateView,  AutorisationListCreateView, AutorisationDetailView, RoleListCreateView  
from .views import   AccountsListCreateView,   LoginView, LogoutView,  AccountGroupListCreateView, AccountGroupDetailView
from .views import HierarchyListCreateView,  HierarchyDetailView, HierarchyItemDetailView,AccountGroupAccountsView, AccountGroupAddAccountsView
from .views import PasswordResetRequestView, PasswordResetView, ChangePasswordView, ProjectsCreateView, ProjectDetailView, PasswordDefineRequestView #AccountGroupPersonalAccountsView
from .views import AccountGroupDeleteAccountsView, HierarchyItemCreateView, AccountGroupAllAccountsView, AccountGroupAllRoleView, PasswordDefineView#HierarchyItemListCreateView,HierarchyItemCreateView
from.views import AddAccreditationView, RoleUpdateView, RoleListView, UpdateRoleAutorisationsView, RoleDetailView, RoleDeactivateView, RoleActivateView#,AddAccreditationGroupView
from.views import UpdateUserView, AssignRolesView, UserDetailsView, AssignUsersToGroup, HierarchyCopyView, GetAccountsListCreateView


urlpatterns = [
    
    path('api/login', LoginView.as_view(), name='login'),
    path('api/logout', LogoutView.as_view()),



    path('api/autorisations-groups/', AutorisationsGroupListCreateView.as_view(), name='autorisations-group-list-create'),
    path('api/autorisations/', AutorisationListCreateView.as_view(), name='autorisation-list-create'),
    path('api/autorisations/<int:pk>/', AutorisationDetailView.as_view(), name='autorisation-detail'),


    
    
    path('api/roles/', RoleListCreateView.as_view(), name='role-list-create'),
    path('api/assign-roles/user/<str:user_identifier>/', AssignRolesView.as_view(), name='assign_user_roles'),
    path('api/assign-roles/group/<str:group_identifier>/', AssignRolesView.as_view(), name='assign_group_roles'),
    path('api/roles/<str:role_identifier>/', RoleUpdateView.as_view(), name='role-update'),  
    path('api/roles-list/', RoleListView.as_view(), name ='role-list'),
    path('api/roles-detail/<str:role_identifier>/', RoleDetailView.as_view(), name='role-detail'),
    path('api/roles-authorization-update/<uuid:role_identifier>/', UpdateRoleAutorisationsView.as_view(), name='update_autorisations'),
    path('api/roles/<uuid:role_identifier>/Deactivated/', RoleDeactivateView.as_view(), name='deactivated-role'),
    path('api/roles/<uuid:role_identifier>/activate/', RoleActivateView.as_view(), name='role_activate'),

    


    path('api/accounts/', AccountsListCreateView.as_view(), name='account-list-create'), # Demande de Creation de compte  

    path('api/user-details/<str:user_identifier>/', UserDetailsView.as_view(), name='user_details'), # detail sur un utilisateur 

    path('api/search-users/', GetAccountsListCreateView.as_view(), name='get-user-list'),

    path('api/users/update/<str:user_identifier>/', UpdateUserView.as_view(), name='users-update'),

    
    path('api/users-group/', AccountGroupListCreateView.as_view(), name='users-group-list'),
    path('api/users-group/<str:group_identifier>/', AccountGroupDetailView.as_view(), name='users-group-detail'),
    path('api/users-group/<str:group_identifier>/all-users/',  AccountGroupAllAccountsView.as_view(), name='users-group-all-accounts'),
    path('api/users-group/<str:group_identifier>/all-roles/', AccountGroupAllRoleView.as_view(), name='users-group-all-roles'),
    path('api/account-groups/accounts/<str:group_identifier>/', AccountGroupAccountsView.as_view(), name='account-group-accounts'),
    path('api/users-group/<str:group_identifier>/add_users/', AccountGroupAddAccountsView.as_view(), name='add_users'),
    path('api/users-group/<str:group_identifier>/remove-users/', AccountGroupDeleteAccountsView.as_view(), name='remove_users'),
    path('api/group/<str:group_identifier>/add-users/', AssignUsersToGroup.as_view(), name='add-users-in-group'),


   # path('api/login', LoginView.as_view()),
    

    path('api/change-password', ChangePasswordView.as_view(), name='change-password'),
    path('api/reset-password/request/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('api/password/define/request/', PasswordDefineRequestView.as_view(), name='password-define'),
    path('password/define/<str:uidb64>/<str:token>/', PasswordDefineView.as_view(), name='password_reset'),
    path('password/reset/<str:uidb64>/<str:token>/', PasswordResetView.as_view(), name='password_reset'),
    path('api/password/change/', ChangePasswordView.as_view(), name= 'password-change'),
    #path('/password/change/', ChangePasswordView.as_view(), name= 'password-change'),
    


    path('api/projects/', ProjectsCreateView.as_view(), name='projects-list-create'),
    path('api/projects/search/', ProjectsCreateView.as_view(), name='projects-list-create'),
    path('api/projects/<str:Project_identifier>/', ProjectDetailView.as_view(), name='project-list-detail'),
    path('api/projects/edit/<str:Project_identifier>/', ProjectDetailView.as_view(), name='project-edit-list-detail'),



    path('api/hierarchies/', HierarchyListCreateView.as_view(), name= 'hierarchies-list-create' ),
    path('api/hierarchies/<str:hierachy_identifier>/', HierarchyDetailView.as_view(), name= 'hierarchies-detail' ),
    path('api/hierarchy-items/',HierarchyItemCreateView.as_view(), name='hierarchyitem-list-create'),
    path('api/hierarchy-items/search/',HierarchyItemCreateView.as_view(), name='hierarchyitem-list-create'),
    path('api/hierarchy-items/<str:HieraItem_identifier>/',HierarchyItemDetailView.as_view(), name='hierarchie-item-detail'),
    
    path('api/hierarchy/copy/', HierarchyCopyView.as_view(), name='hierarchy_copy'),

    


    path('api/accreditations/abstract-user/<str:user_identifier>/update/', AddAccreditationView.as_view(), name='add_accreditation'),










   # path('api/add-accreditation-Group/<str:group_identifier>/', AddAccreditationGroupView.as_view(), name='add_accreditation-group'),
    #path('api/users-group/', CreateAccountGroup.as_view(), name='users-group-list'),
    #path('api/account-groups/accounts/personal/<str:group_identifier>/<str:identifier>/', AccountGroupPersonalAccountsView.as_view(), name='personal_accounts')
   # path('api/account-groups/add_users/<str:group_identifier>/', AccountGroupAccountsView.as_view(), name='add_users')

       
]
