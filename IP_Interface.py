import re
from nautobot_data_validation_engine.custom_validators import DataComplianceRule, ComplianceError

class DesiredClassName(DataComplianceRule):
    model = "ipam.ipaddress" # Ex: 'dcim.device'
    enforce = True # True/False enforce flag

    def audit_desired_ip_interface_assignment(self):
        if self.context["object"].interfaces.count() > 1:
            raise ComplianceError({
                "desired_attribute": "IP interface must have only 1 interface assigned"
            })

    def audit(self):
        messages = {}
        for fn in [self.audit_desired_ip_interface_assignment]:
            try:
                fn()
            except ComplianceError as ex:
                messages.update(ex.message_dict)
        if messages:
            raise ComplianceError(messages)