rule rule_AMSI_Provider_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AMSI-Provider' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AMSI-Provider"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AMSI_Provider_offensive_tool_keyword = /\/AMSI\-Provider\.git/ nocase ascii wide
                        $string2_AMSI_Provider_offensive_tool_keyword = /\\AmsiProvider\.cpp/ nocase ascii wide
                        $string3_AMSI_Provider_offensive_tool_keyword = /\\AmsiProvider\.sln/ nocase ascii wide
                        $string4_AMSI_Provider_offensive_tool_keyword = /\\AMSI\-Provider\-main/ nocase ascii wide
                        $string5_AMSI_Provider_offensive_tool_keyword = "58B32FCA-F385-4500-9A8E-7CBA1FC9BA13" nocase ascii wide
                        $string6_AMSI_Provider_offensive_tool_keyword = "7a9a81c7ef99897281466ea06c14886335cf8d4c835f15aeb1e3a2c7c1d0e760" nocase ascii wide
                        $string7_AMSI_Provider_offensive_tool_keyword = "90bf7beb921839957e7977851f01e757346d2b4f672e6a08b04e57878cd6efbf" nocase ascii wide
                        $string8_AMSI_Provider_offensive_tool_keyword = "b4a7045568cb78f48f42b93f528e14ef24f8dc3bf878af0b94ca22c5df546da5" nocase ascii wide
                        $string9_AMSI_Provider_offensive_tool_keyword = "netbiosX/AMSI-Provider" nocase ascii wide

    condition:
        any of them
}