rule DumpLSASS
{
    meta:
        description = "Detection patterns for the tool 'DumpLSASS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpLSASS"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "ATK/MultiDump-" nocase ascii wide
                        $string2 = /HackTool\.LsassDumper/ nocase ascii wide

    condition:
        any of them
}