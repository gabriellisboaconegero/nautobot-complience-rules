import re
from nautobot_data_validation_engine.custom_validators import DataComplianceRule, ComplianceError
from nautobot.dcim.models import LocationType
from nautobot.extras.models import Status
from django.core.exceptions import ObjectDoesNotExist

INTERFACE_TEMPLATES = [
    {"name": "WAN1", "type": "gpon"},
    {"name": "WAN2", "type": "gpon"}
]

class ClientCompliance(DataComplianceRule):
    model = "dcim.device" # Ex: 'dcim.device'
    # enforce = True # True/False enforce flag

    # 1. Verificar regex do nome
    def audit_name(self, device):
        if not re.match(r"^\w+\|\d+$", device.name):
            raise ComplianceError({
                "error": "Nome do cliente deve ser do formato TENANT|IDENTIFICADOR",
                "client_name": device.name,
            })

    # 1. Verificar se tem tenant
    def audit_tenant(self, device):
        if device.tenant == None:
            raise ComplianceError({
                "error": "Cliente deve ter um Tenant",
            })

    # 1. Verificar se location é do tenant escolhido
    # 2. Verificar se location é do tipo 'Datacenter"
    # 3. Verificar se location tem prefix
    def audit_location(self, device):
        if not device.location.tenant == device.tenant:
            raise ComplianceError({
                "error": "Tenant da location do cliente deve ser a mesma do tenant do Cliente.",
                "client_tenant": device.tenant,
                "location_tenant": device.location.tenant,
            })
        
        DatacenterLocationType = LocationType.objects.get(name="Datacenter")

        if device.location.location_type != DatacenterLocationType:
            raise ComplianceError({
                "error": "Client location deve ser do tipo 'Datacenter'",
                "client_location_type": device.location.location_type,
            })

        if not device.location.prefixes.exists():
            raise ComplianceError({
                "error": "Client location deve ter pelo menos um prefix",
            })
    
    # 1. Verificar se device tem 2 interfaces
    # 2. Verificar se ambas interface tem nome WAN1 e WAN2 respectivamente
    # 3. Verificar se ambas interfaces tem tipo GPON
    def audit_interfaces(self, device):
        try:
            for interface_args in INTERFACE_TEMPLATES:
                device.interfaces.get(**interface_args)
        except ObjectDoesNotExist:
            raise ComplianceError({
                "error": "Pelo menos duas interfaces com nomes WAN1 e WAN2, respectivamente, devem existir. Ambas devem ser do tipo 'GPON'",
                "interfaces": ",".join([f"{i.name}: {i.type}" for i in device.interfaces.all()])
            })
    
    # 1. Verificar se device tem primary IPv4 se tiver ativo
    def audit_ip_address(self, device):
        DeviceActiveStatus = Status.objects.get(name="Active", content_types__model="device")

        if device.status != DeviceActiveStatus and device.primary_ip == None:
            raise ComplianceError({
                "error": "Client deve ter primary IPv4",
            })
    
    
    def audit(self):
        messages = {}
        # Veririfica se é um cliente (tem tag de Fix IP)
        if not self.context["object"].tags.filter(tags__name="Fix IP").exists():
            return

        for fn in [self.audit_name]:
            try:
                fn(self.context["object"])
            except ComplianceError as ex:
                messages[fn.__name__] = ex.message_dict
        if messages:
            raise ComplianceError(messages)