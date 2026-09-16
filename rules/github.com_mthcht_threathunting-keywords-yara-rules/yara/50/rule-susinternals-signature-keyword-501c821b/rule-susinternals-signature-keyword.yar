rule rule_susinternals_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'susinternals' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "susinternals"
        rule_category = "signature_keyword"

    strings:
                        $string1_susinternals_signature_keyword = /HEUR\:HackTool\.Python\.Impacket\.gen/ nocase ascii wide
                        $string2_susinternals_signature_keyword = /VirTool\:Python\/RemoteSvcExecute\.A/ nocase ascii wide

    condition:
        any of them
}