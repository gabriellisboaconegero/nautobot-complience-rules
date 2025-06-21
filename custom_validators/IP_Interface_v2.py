# nautobot-compliance-rules/ip_rules.py

from nautobot_data_validation_engine.choices import DataComplianceStatusChoices
from nautobot_data_validation_engine.registry import DataComplianceRule
from nautobot.dcim.models import Interface
from nautobot.ipam.models import IPAddress

class UniqueIPInterfaceAssignmentRule(DataComplianceRule):
    """
    Ensures that an IP address is assigned to at most one interface.
    """
    model = "ipam.ipaddress"  # The model this rule applies to
    name = "Unique IP per Interface Assignment"
    description = "Checks if an IP address is assigned to more than one interface."

    def check_compliance(self, obj: IPAddress):
        """
        Checks if the given IPAddress object is assigned to more than one interface.
        """
        # In Nautobot v2.0+, IPAddress can be assigned to multiple interfaces.
        # We need to check the count of interfaces linked to this IP.
        assigned_interfaces_count = obj.assigned_interfaces.count()

        if assigned_interfaces_count > 1:
            return DataComplianceStatusChoices.STATUS_FAIL, f"IP address {obj.address} is assigned to multiple interfaces: {', '.join([str(iface) for iface in obj.assigned_interfaces.all()])}"
        else:
            return DataComplianceStatusChoices.STATUS_PASS, f"IP address {obj.address} is assigned to one or zero interfaces."