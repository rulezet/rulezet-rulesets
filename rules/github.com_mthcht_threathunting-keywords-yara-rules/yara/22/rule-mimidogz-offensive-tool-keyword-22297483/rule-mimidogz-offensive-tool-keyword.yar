rule rule_mimidogz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mimidogz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimidogz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_mimidogz_offensive_tool_keyword = " -DumpCred -ComputerName @" nocase ascii wide
                        $string2_mimidogz_offensive_tool_keyword = " -DumpCreds -ComputerName @" nocase ascii wide
                        $string3_mimidogz_offensive_tool_keyword = /\$ThisIsNotTheStringYouAreLookingFor/ nocase ascii wide
                        $string4_mimidogz_offensive_tool_keyword = /\/mimidogz\.git/ nocase ascii wide
                        $string5_mimidogz_offensive_tool_keyword = /\\mimidogz\-master/ nocase ascii wide
                        $string6_mimidogz_offensive_tool_keyword = "CallDllMainSC1/ThisIsNotTheStringYouAreLookingFor" nocase ascii wide
                        $string7_mimidogz_offensive_tool_keyword = "f2ee8facc06d5525d4bb73e079e8b599a0a2893351193013ba45ca311dbac50e" nocase ascii wide
                        $string8_mimidogz_offensive_tool_keyword = "fir3d0g/mimidogz" nocase ascii wide
                        $string9_mimidogz_offensive_tool_keyword = /https\:\/\/www\.blackhillsinfosec\.com\/bypass\-anti\-virus\-run\-mimikatz/ nocase ascii wide
                        $string10_mimidogz_offensive_tool_keyword = /Invoke\-Dogz\.ps1/ nocase ascii wide
                        $string11_mimidogz_offensive_tool_keyword = "Invoke-MimiDoggies" nocase ascii wide
                        $string12_mimidogz_offensive_tool_keyword = "Invoke-Mimidogz" nocase ascii wide
                        $string13_mimidogz_offensive_tool_keyword = /Invoke\-Mimidogz\.ps1/ nocase ascii wide
                        $string14_mimidogz_offensive_tool_keyword = /mimidogz\-master\.zip/ nocase ascii wide
                        $string15_mimidogz_offensive_tool_keyword = "projectb-temp/mimidogz" nocase ascii wide
                        $string16_mimidogz_offensive_tool_keyword = "sed -i -e 's/ArgumentPtr/NotTodayPal/" nocase ascii wide

    condition:
        any of them
}