rule rule_merlin_agent_dll_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'merlin-agent-dll' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin-agent-dll"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_merlin_agent_dll_offensive_tool_keyword = /\smerlin\.dll/ nocase ascii wide
                        $string2_merlin_agent_dll_offensive_tool_keyword = /\/merlin\.dll/ nocase ascii wide
                        $string3_merlin_agent_dll_offensive_tool_keyword = /\/merlin\-agent\-dll\.git/ nocase ascii wide
                        $string4_merlin_agent_dll_offensive_tool_keyword = "/merlin-agent-dll/" nocase ascii wide
                        $string5_merlin_agent_dll_offensive_tool_keyword = /\[\+\]\sHello\sfrom\sDllMain\-PROCESS_ATTACH\sin\sMerlin/ nocase ascii wide
                        $string6_merlin_agent_dll_offensive_tool_keyword = /\\merlin\.dll/ nocase ascii wide
                        $string7_merlin_agent_dll_offensive_tool_keyword = /\\merlin\-agent\-dll\\/ nocase ascii wide
                        $string8_merlin_agent_dll_offensive_tool_keyword = "5FAE766D503C33AD0AE90520BFA0ADA54FFC6FF998B0542D1CF63D94B4126E3F" nocase ascii wide
                        $string9_merlin_agent_dll_offensive_tool_keyword = "8d013a3cd78fc557c13657fbdf62382cace60d05dc73868184db4a5573bca34e" nocase ascii wide
                        $string10_merlin_agent_dll_offensive_tool_keyword = "cmd/merlinagentdll/" nocase ascii wide
                        $string11_merlin_agent_dll_offensive_tool_keyword = "Hello from DllMain-PROCESS_ATTACH in Merlin!" nocase ascii wide
                        $string12_merlin_agent_dll_offensive_tool_keyword = /Invoke\-ReflectivePEInjection\.ps1/ nocase ascii wide
                        $string13_merlin_agent_dll_offensive_tool_keyword = /merlin\-agent\-dll\.7z/ nocase ascii wide
                        $string14_merlin_agent_dll_offensive_tool_keyword = "merlin-agent-dll/tarball/v" nocase ascii wide
                        $string15_merlin_agent_dll_offensive_tool_keyword = "merlin-agent-dll/zipball/v" nocase ascii wide
                        $string16_merlin_agent_dll_offensive_tool_keyword = /merlin\-agent\-dll\\merlin\./ nocase ascii wide
                        $string17_merlin_agent_dll_offensive_tool_keyword = /merlin\-c2\.readthedocs\.io/ nocase ascii wide
                        $string18_merlin_agent_dll_offensive_tool_keyword = "Ne0nd0g/merlin-agent-dll" nocase ascii wide
                        $string19_merlin_agent_dll_offensive_tool_keyword = /VoidFunc\sis\san\sexported\sfunction\sused\swith\sPowerSploit\'s\sInvoke\-ReflectivePEInjection\.ps1/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}