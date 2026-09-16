rule merlin_agent_dll
{
    meta:
        description = "Detection patterns for the tool 'merlin-agent-dll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin-agent-dll"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\smerlin\.dll/ nocase ascii wide
                        $string2 = /\/merlin\.dll/ nocase ascii wide
                        $string3 = /\/merlin\-agent\-dll\.git/ nocase ascii wide
                        $string4 = "/merlin-agent-dll/" nocase ascii wide
                        $string5 = /\[\+\]\sHello\sfrom\sDllMain\-PROCESS_ATTACH\sin\sMerlin/ nocase ascii wide
                        $string6 = /\\merlin\.dll/ nocase ascii wide
                        $string7 = /\\merlin\-agent\-dll\\/ nocase ascii wide
                        $string8 = "5FAE766D503C33AD0AE90520BFA0ADA54FFC6FF998B0542D1CF63D94B4126E3F" nocase ascii wide
                        $string9 = "8d013a3cd78fc557c13657fbdf62382cace60d05dc73868184db4a5573bca34e" nocase ascii wide
                        $string10 = "cmd/merlinagentdll/" nocase ascii wide
                        $string11 = "Hello from DllMain-PROCESS_ATTACH in Merlin!" nocase ascii wide
                        $string12 = /Invoke\-ReflectivePEInjection\.ps1/ nocase ascii wide
                        $string13 = /merlin\-agent\-dll\.7z/ nocase ascii wide
                        $string14 = "merlin-agent-dll/tarball/v" nocase ascii wide
                        $string15 = "merlin-agent-dll/zipball/v" nocase ascii wide
                        $string16 = /merlin\-agent\-dll\\merlin\./ nocase ascii wide
                        $string17 = /merlin\-c2\.readthedocs\.io/ nocase ascii wide
                        $string18 = "Ne0nd0g/merlin-agent-dll" nocase ascii wide
                        $string19 = /VoidFunc\sis\san\sexported\sfunction\sused\swith\sPowerSploit\'s\sInvoke\-ReflectivePEInjection\.ps1/ nocase ascii wide

    condition:
        any of them
}