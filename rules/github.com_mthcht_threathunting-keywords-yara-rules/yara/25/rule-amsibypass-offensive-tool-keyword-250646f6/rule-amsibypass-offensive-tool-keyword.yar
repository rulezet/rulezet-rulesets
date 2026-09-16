rule rule_AmsiBypass_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AmsiBypass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AmsiBypass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AmsiBypass_offensive_tool_keyword = /\/AmsiBypass\./ nocase ascii wide
                        $string2_AmsiBypass_offensive_tool_keyword = /\/Amsi\-Bypass\-Powershell\.git/ nocase ascii wide
                        $string3_AmsiBypass_offensive_tool_keyword = "/opt/Projects/AmsiBypass/"
                        $string4_AmsiBypass_offensive_tool_keyword = /\\AmsiBypass\./ nocase ascii wide
                        $string5_AmsiBypass_offensive_tool_keyword = "132ab5d9aa388ae3a6575a01fadeb7fa7f77aac1150fc54bc1d20ae32b58ddc5" nocase ascii wide
                        $string6_AmsiBypass_offensive_tool_keyword = "Invoke-PsUACme -Method " nocase ascii wide
                        $string7_AmsiBypass_offensive_tool_keyword = "Modified-Amsi-ScanBuffer-Patch" nocase ascii wide
                        $string8_AmsiBypass_offensive_tool_keyword = "Nishang-all-in-one" nocase ascii wide
                        $string9_AmsiBypass_offensive_tool_keyword = "Patching-AMSI-AmsiScanBuffer-by-rasta-mouse" nocase ascii wide
                        $string10_AmsiBypass_offensive_tool_keyword = "S3cur3Th1sSh1t/Amsi-Bypass-Powershell" nocase ascii wide
                        $string11_AmsiBypass_offensive_tool_keyword = /\'System\.Ma\'\+\'nag\'\+\'eme\'\+\'nt\.Autom\'\+\'ation\.A\'\+\'ms\'\+\'iU\'\+\'ti\'\+\'ls\'/ nocase ascii wide
                        $string12_AmsiBypass_offensive_tool_keyword = "Tztufn/Nbobhfnfou/Bvupnbujpo/BntjVujmt" nocase ascii wide

    condition:
        any of them
}