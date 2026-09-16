rule PayGen
{
    meta:
        description = "Detection patterns for the tool 'PayGen' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PayGen"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/signer\-exe\.py/ nocase ascii wide
                        $string2 = /PayGen.{0,1000}python3\sgenerate\.py/ nocase ascii wide
                        $string3 = /shellcode\-exec\.ps1/ nocase ascii wide
                        $string4 = /shellcode\-runner\.py/ nocase ascii wide
                        $string5 = "youhacker55/PayGen" nocase ascii wide
                        $string6 = "cd PayGen" nocase ascii wide

    condition:
        any of them
}