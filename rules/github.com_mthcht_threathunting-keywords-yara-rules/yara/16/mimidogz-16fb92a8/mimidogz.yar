rule mimidogz
{
    meta:
        description = "Detection patterns for the tool 'mimidogz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimidogz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -DumpCred -ComputerName @" nocase ascii wide
                        $string2 = " -DumpCreds -ComputerName @" nocase ascii wide
                        $string3 = /\$ThisIsNotTheStringYouAreLookingFor/ nocase ascii wide
                        $string4 = /\/mimidogz\.git/ nocase ascii wide
                        $string5 = /\\mimidogz\-master/ nocase ascii wide
                        $string6 = "CallDllMainSC1/ThisIsNotTheStringYouAreLookingFor" nocase ascii wide
                        $string7 = "f2ee8facc06d5525d4bb73e079e8b599a0a2893351193013ba45ca311dbac50e" nocase ascii wide
                        $string8 = "fir3d0g/mimidogz" nocase ascii wide
                        $string9 = /https\:\/\/www\.blackhillsinfosec\.com\/bypass\-anti\-virus\-run\-mimikatz/ nocase ascii wide
                        $string10 = /Invoke\-Dogz\.ps1/ nocase ascii wide
                        $string11 = "Invoke-MimiDoggies" nocase ascii wide
                        $string12 = "Invoke-Mimidogz" nocase ascii wide
                        $string13 = /Invoke\-Mimidogz\.ps1/ nocase ascii wide
                        $string14 = /mimidogz\-master\.zip/ nocase ascii wide
                        $string15 = "projectb-temp/mimidogz" nocase ascii wide
                        $string16 = "sed -i -e 's/ArgumentPtr/NotTodayPal/" nocase ascii wide

    condition:
        any of them
}