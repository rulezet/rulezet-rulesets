rule rule_SweetPotato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SweetPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SweetPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SweetPotato_offensive_tool_keyword = " --exploit=DCOM" nocase ascii wide
                        $string2_SweetPotato_offensive_tool_keyword = " --exploit=DCOM" nocase ascii wide
                        $string3_SweetPotato_offensive_tool_keyword = " --exploit=EfsRpc" nocase ascii wide
                        $string4_SweetPotato_offensive_tool_keyword = " --exploit=PrintSpoofer" nocase ascii wide
                        $string5_SweetPotato_offensive_tool_keyword = " --exploit=WinRM" nocase ascii wide
                        $string6_SweetPotato_offensive_tool_keyword = /\sSweetpotato\.exe/ nocase ascii wide
                        $string7_SweetPotato_offensive_tool_keyword = /\/Sweetpotato\.exe/ nocase ascii wide
                        $string8_SweetPotato_offensive_tool_keyword = /\/SweetPotato\.git/ nocase ascii wide
                        $string9_SweetPotato_offensive_tool_keyword = /\/SweetPotato\-master\.zip/ nocase ascii wide
                        $string10_SweetPotato_offensive_tool_keyword = /\[\+\]\sAttempting\sDCOM\sNTLM\srelaying\swith\sCLSID/ nocase ascii wide
                        $string11_SweetPotato_offensive_tool_keyword = /\[\+\]\sAttempting\sNP\simpersonation\susing\smethod\sEfsRpc\sto\slaunch\s/ nocase ascii wide
                        $string12_SweetPotato_offensive_tool_keyword = /\[\+\]\sAttempting\sNP\simpersonation\susing\smethod\sPrintSpoofer\sto\slaunch\s/ nocase ascii wide
                        $string13_SweetPotato_offensive_tool_keyword = /\[\+\]\sServer\sconnected\sto\sour\sevil\sRPC\spipe/ nocase ascii wide
                        $string14_SweetPotato_offensive_tool_keyword = /\[\+\]\sTriggering\sname\spipe\saccess\son\sevil\sPIPE\s/ nocase ascii wide
                        $string15_SweetPotato_offensive_tool_keyword = /\\Sweetpotato\.exe/ nocase ascii wide
                        $string16_SweetPotato_offensive_tool_keyword = /\\SweetPotato\\Program\.cs/ nocase ascii wide
                        $string17_SweetPotato_offensive_tool_keyword = /\\SweetPotato\-master\.zip/ nocase ascii wide
                        $string18_SweetPotato_offensive_tool_keyword = "1BF9C10F-6F89-4520-9D2E-AAF17D17BA5E" nocase ascii wide
                        $string19_SweetPotato_offensive_tool_keyword = "8f2a1d66e0a532a030da8e0e646f866ea91ee987ffb33b36d95f64a0538a3e20" nocase ascii wide
                        $string20_SweetPotato_offensive_tool_keyword = "CCob/SweetPotato" nocase ascii wide
                        $string21_SweetPotato_offensive_tool_keyword = /PotatoAPI\.Mode\.DCOMRemote/ nocase ascii wide
                        $string22_SweetPotato_offensive_tool_keyword = "Remote Potato by @decoder_it and @splinter_code" nocase ascii wide
                        $string23_SweetPotato_offensive_tool_keyword = "SweetPotato by @_EthicalChaos_" nocase ascii wide
                        $string24_SweetPotato_offensive_tool_keyword = "Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}