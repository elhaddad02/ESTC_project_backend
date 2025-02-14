# views.py
import logging
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.exceptions import NotFound
from django.http import Http404  
from .serializers import *
from authentication.permissions import IsParentAuthenticated
from authentication.models import Parent, Student
from students.models import Insurance
from students.serializers import StudentProfileSerializer, InsuranceSerializer,TicketingServiceSerializer, HousingSearchSerializer
from rest_framework.views import APIView

logger = logging.getLogger(__name__)

class ParentRegistrationView(generics.CreateAPIView):
    serializer_class = ParentRegistrationSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        logger.info('Received registration request: %s', request.data)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        parent = serializer.save()
        response_data = {
            "parent": serializer.data,
            "message": "Parent created successfully and linked to the student."
        }
        logger.info('Parent created successfully: %s', parent)
        return Response(response_data, status=status.HTTP_201_CREATED)

class ParentProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = ParentProfileSerializer
    permission_classes = [IsAuthenticated, IsParentAuthenticated]

    def get_object(self):
        try:
            return self.request.user.parent_profile
        except Parent.DoesNotExist:
            raise NotFound("Parent does not exist")

    def get(self, request, *args, **kwargs):
        parent = self.get_object()
        serializer = self.get_serializer(parent)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        parent = self.get_object()
        serializer = self.get_serializer(parent, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        parent = self.get_object()
        serializer = self.get_serializer(parent, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

class ParentChildProfileView(generics.RetrieveAPIView):
    serializer_class = StudentProfileSerializer
    permission_classes = [IsAuthenticated, IsParentAuthenticated]

    def get_object(self):
        parent = self.request.user.parent_profile
        if not parent:
            logger.error('Parent does not exist for user: %s', self.request.user)
            raise NotFound("Parent does not exist")

        student = parent.children.first()  # Correct the related name to 'children'
        if not student:
            logger.error('Student does not exist for parent: %s', parent)
            raise NotFound("Student does not exist")

        return student

    def get(self, request, *args, **kwargs):
        student = self.get_object()
        serializer = self.get_serializer(student)
        return Response(serializer.data)

class ParentHousingStatusView(generics.ListAPIView):
    serializer_class = ChildHousingStatusSerializer
    permission_classes = [IsAuthenticated, IsParentAuthenticated]

    def get_queryset(self):
        parent = self.request.user.parent_profile
        students = parent.children.all()  # Assume `children` is a related name for the parent's children
        return HousingSearch.objects.filter(user__student__in=students)
    
class ParentTicketingStatusView(generics.ListAPIView):
    serializer_class = ChildTicketingStatusSerializer
    permission_classes = [IsAuthenticated, IsParentAuthenticated]

    def get_queryset(self):
        parent = self.request.user.parent_profile
        students = parent.children.all()  # Assume `children` is a related name for the parent's children
        return TicketingService.objects.filter(user__student__in=students)
    
class ParentInsuranceStatusView(generics.ListAPIView):
    serializer_class = InsuranceSerializer
    permission_classes = [IsAuthenticated, IsParentAuthenticated]

    def get_queryset(self):
        parent = self.request.user.parent_profile
        students = parent.children.all()
        insurances = Insurance.objects.filter(user__student__in=students)
        return insurances
    
class ParentPaymentHistoryView(generics.ListAPIView):
    serializer_class = ChildPaymentSerializer
    permission_classes = [IsAuthenticated, IsParentAuthenticated]

    def get_queryset(self):
        parent = self.request.user.parent_profile
        students = parent.children.all()
        payments = Payment.objects.filter(user__student__in=students)
        return 
    
# class ParentChildCandidateListView(generics.ListAPIView):
#     serializer_class = ChildCandidateSerializer
#     permission_classes = [IsAuthenticated, IsParentAuthenticated]

#     def get_queryset(self):
#         parent = self.request.user.parent_profile
#         children = parent.children.all()
#         children_emails = [child.user.email for child in children]
#         return Candidate.objects.filter(email__in=children_emails)
    
class ParentPaymentHistoryView(generics.ListAPIView):
    serializer_class = ChildPaymentSerializer
    permission_classes = [IsAuthenticated, IsParentAuthenticated]

    def get_queryset(self):
        parent = self.request.user.parent_profile
        students = parent.children.all()
        payments = Payment.objects.filter(user__student__in=students)
        return payments
 
  
'''class ParentIrrevocablePaymentCertificateView(generics.ListAPIView):
    serializer_class = IrrevocablePaymentCertificateSerializer
    permission_classes = [IsAuthenticated, IsParentAuthenticated]

    def get(self, request, *args, **kwargs):
        parent = self.request.user.parent_profile
        students = parent.children.all()
        payment_certificate = IrrevocablePaymentCertificate.objects.filter(
            user__student__in=students
        ).first()
        if not payment_certificate:
            raise Http404("No payment certificate found for the given students.")
        serializer = self.serializer_class(payment_certificate)
        return Response(serializer.data)'''

class ParentIrrevocablePaymentCertificateView(generics.ListAPIView):
    serializer_class = IrrevocablePaymentCertificateSerializer
    permission_classes = [IsAuthenticated, IsParentAuthenticated]

    def get_queryset(self):
        parent = self.request.user.parent_profile
        students = parent.children.all()
        return IrrevocablePaymentCertificate.objects.filter(user__student__in=students)

class ServiceAbonAPIViewParent(APIView):
    permission_classes = [IsAuthenticated, IsParentAuthenticated]

    def get(self, request):
        parent = request.user.parent_profile
        students = parent.children.all()
        student_names = parent.children.all()
        student_names = students.first()
        service_count = (
            IrrevocablePaymentCertificate.objects.filter(user__id__in=[s.user.id for s in students]).count() +
            Insurance.objects.filter(user__id__in=[s.user.id for s in students]).count() +
            HousingSearch.objects.filter(user__id__in=[s.user.id for s in students]).count() +
            TicketingService.objects.filter(user__id__in=[s.user.id for s in students]).count()
        )

        return Response({"services_abon": service_count,"student_names":  student_names.user.first_name})

class ParentChildServiceFilesAPIView(APIView):
    permission_classes = [IsAuthenticated, IsParentAuthenticated]

    def get(self, request, *args, **kwargs):
        # Récupération du parent
        parent = self.request.user.parent_profile
        
        # Récupération des enfants associés au parent
        children = parent.children.all()  # Utilisation de related_name pour récupérer les enfants
        
        if not children:
            return Response(
                {"detail": "Aucun enfant associé trouvé pour ce parent."},
                status=status.HTTP_404_NOT_FOUND,
            )
        
        # Initialiser les dictionnaires pour stocker les fichiers des services
        services_files = {
            "irrevocable_payments": [],
            "insurances": [],
            "housing": [],
            "ticketing": []
        }

        # Récupération des services pour chaque enfant
        for child in children:
            # Récupérer les certificats de paiement irrévocables (exemple)
            irrevocable_payments = IrrevocablePaymentCertificate.objects.filter(user=child.user)
            insurances = Insurance.objects.filter(user=child.user)
            housing_searches = HousingSearch.objects.filter(user=child.user)
            ticketing_services = TicketingService.objects.filter(user=child.user)
            
            # Sérialisation des données
            irrevocable_serializer = IrrevocablePaymentCertificateSerializer(irrevocable_payments, many=True)
            insurance_serializer = InsuranceSerializer(insurances, many=True)
            housing_serializer = HousingSearchSerializer(housing_searches, many=True)
            ticketing_serializer = TicketingServiceSerializer(ticketing_services, many=True)

            # Extraction des fichiers uniquement et filtrage des valeurs nulles
            services_files["irrevocable_payments"].extend(
                [item.get("files") for item in irrevocable_serializer.data if item.get("files")]
            )
            
            services_files["insurances"].extend(
                [item.get("files") for item in insurance_serializer.data if item.get("files")]
            )
            services_files["housing"].extend(
                [item.get("files") for item in housing_serializer.data if item.get("files")]
            )
            services_files["ticketing"].extend(
                [item.get("files") for item in ticketing_serializer.data if item.get("files")]
            )

        # Retourner les résultats sous forme de réponse JSON
        return Response({
            "children": [
                {
                    "child_name": f"{child.user.first_name} {child.user.last_name}",
                    "services_files": {
                        "irrevocable_payments": [file for file in services_files["irrevocable_payments"]],
                        "insurances": [file for file in services_files["insurances"]],
                        "housing": [file for file in services_files["housing"]],
                        "ticketing": [file for file in services_files["ticketing"]],
                    }
                } for child in children
            ]
        }, status=status.HTTP_200_OK)

# class ParentChildServiceFilesAPIView(APIView):
#     permission_classes = [IsAuthenticated, IsParentAuthenticated]

#     def get(self, request, *args, **kwargs):
#         parent = self.request.user.parent_profile
        
#         # Récupération de l'enfant lié au parent
#         students = parent.children.all()  # Utilisation de related_name pour récupérer les enfants
        
#         if not students:
#             return Response(
#                 {"detail": "Aucun enfant associé trouvé pour ce parent."},
#                 status=status.HTTP_404_NOT_FOUND,
#             )

#         # Récupération des services liés aux enfants
#         irrevocable_payments = IrrevocablePaymentCertificate.objects.filter(user__student__in=students)
#         insurances = Insurance.objects.filter(user__student__in=students)
#         housing_searches = HousingSearch.objects.filter(user__student__in=students)
#         ticketing_services = TicketingService.objects.filter(user__student__in=students)

#         # Sérialisation des données
#         irrevocable_serializer = IrrevocablePaymentCertificateSerializer(irrevocable_payments, many=True)
#         insurance_serializer = InsuranceSerializer(insurances, many=True)
#         housing_serializer = ChildHousingStatusSerializer(housing_searches, many=True)
#         ticketing_serializer = ChildTicketingStatusSerializer(ticketing_services, many=True)

#         # Validation des sérializers et gestion des erreurs
      
#         # Extraction des fichiers uniquement
#         services_files = {
#             "irrevocable_payments": [item.get("files") for item in irrevocable_serializer.data if item.get("files")],
#             "insurances": [item.get("files") for item in insurance_serializer.data if item.get("files")],
#             "housing": [item.get("files") for item in housing_serializer.data if item.get("files")],
#             "ticketing": [item.get("files") for item in ticketing_serializer.data if item.get("files")],
#         }

#         # Si aucune donnée n'est trouvée pour les fichiers, ajoutez un message explicite.
#         if not any(services_files.values()):
#             return Response({"detail": "Aucun fichier trouvé pour les services."}, status=status.HTTP_404_NOT_FOUND)

#         return Response({
#             "child_names": [f"{child.user.first_name} {child.user.last_name}" for child in students],
#             "services_files": services_files
#         }, status=status.HTTP_200_OK)