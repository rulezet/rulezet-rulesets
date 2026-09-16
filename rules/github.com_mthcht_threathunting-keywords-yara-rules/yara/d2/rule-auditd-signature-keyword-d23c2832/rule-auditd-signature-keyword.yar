rule rule_auditd_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'auditd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "auditd"
        rule_category = "signature_keyword"

    strings:
                        $string1_auditd_signature_keyword = "HackTool:Linux/AuditdTamper"

    condition:
        any of them
}