rule rule_Godzilla_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'Godzilla' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Godzilla"
        rule_category = "signature_keyword"

    strings:
                        $string1_Godzilla_signature_keyword = /Backdoor\:ASP\/Chopper\.ZC\!dha/ nocase ascii wide
                        $string2_Godzilla_signature_keyword = "TrojanDownloader:Java/GodzillaWebShell" nocase ascii wide
                        $string3_Godzilla_signature_keyword = /TrojanDownloader\:Java\/GodzillaWebShell\.C/ nocase ascii wide
                        $string4_Godzilla_signature_keyword = /VirTool\:MSIL\/DarkStealer\.A\!MTB/ nocase ascii wide

    condition:
        any of them
}