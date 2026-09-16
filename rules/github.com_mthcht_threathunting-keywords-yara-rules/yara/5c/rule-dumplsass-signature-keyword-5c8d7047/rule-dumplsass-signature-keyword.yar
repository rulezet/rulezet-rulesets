rule rule_DumpLSASS_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'DumpLSASS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpLSASS"
        rule_category = "signature_keyword"

    strings:
                        $string1_DumpLSASS_signature_keyword = "ATK/MultiDump-" nocase ascii wide
                        $string2_DumpLSASS_signature_keyword = /HackTool\.LsassDumper/ nocase ascii wide

    condition:
        any of them
}