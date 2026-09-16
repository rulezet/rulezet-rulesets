rule rule_NetNTLMtoSilverTicket_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NetNTLMtoSilverTicket' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetNTLMtoSilverTicket"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NetNTLMtoSilverTicket_offensive_tool_keyword = /\sdementor\.py/ nocase ascii wide
                        $string2_NetNTLMtoSilverTicket_offensive_tool_keyword = /\sGet\-SpoolStatus\.ps1/ nocase ascii wide
                        $string3_NetNTLMtoSilverTicket_offensive_tool_keyword = /\srpcdump\.py/ nocase ascii wide
                        $string4_NetNTLMtoSilverTicket_offensive_tool_keyword = /\.\/hashcat\s\-/
                        $string5_NetNTLMtoSilverTicket_offensive_tool_keyword = /\/dementor\.py/ nocase ascii wide
                        $string6_NetNTLMtoSilverTicket_offensive_tool_keyword = "/NetNTLMtoSilverTicket" nocase ascii wide
                        $string7_NetNTLMtoSilverTicket_offensive_tool_keyword = /\/rpcdump\.py/ nocase ascii wide
                        $string8_NetNTLMtoSilverTicket_offensive_tool_keyword = /\/ticketer\.py\s\-/
                        $string9_NetNTLMtoSilverTicket_offensive_tool_keyword = /\\dementor\.py/ nocase ascii wide
                        $string10_NetNTLMtoSilverTicket_offensive_tool_keyword = /\\Get\-SpoolStatus\.ps1/ nocase ascii wide
                        $string11_NetNTLMtoSilverTicket_offensive_tool_keyword = /\\rpcdump\.py/ nocase ascii wide
                        $string12_NetNTLMtoSilverTicket_offensive_tool_keyword = "a8421a872b4c4eccc02a0ebb623f9ecc2991e949e4134fc184ca1822da0e5c4c" nocase ascii wide
                        $string13_NetNTLMtoSilverTicket_offensive_tool_keyword = "dementor - rough PoC to connect to spoolss to elicit machine account authentication " nocase ascii wide
                        $string14_NetNTLMtoSilverTicket_offensive_tool_keyword = /dementor\.py\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s/ nocase ascii wide
                        $string15_NetNTLMtoSilverTicket_offensive_tool_keyword = /Got\sexpected\sRPC_S_SERVER_UNAVAILABLE\sexception\.\sAttack\sworked/ nocase ascii wide
                        $string16_NetNTLMtoSilverTicket_offensive_tool_keyword = /impacket\.dcerpc\.v5/ nocase ascii wide
                        $string17_NetNTLMtoSilverTicket_offensive_tool_keyword = /NetNTLMtoSilverTicket\.git/ nocase ascii wide
                        $string18_NetNTLMtoSilverTicket_offensive_tool_keyword = "NetNTLMtoSilverTicket-master" nocase ascii wide
                        $string19_NetNTLMtoSilverTicket_offensive_tool_keyword = /ntlmv1\.py\s\-\-ntlmv1\s.{0,100}\:\:/ nocase ascii wide
                        $string20_NetNTLMtoSilverTicket_offensive_tool_keyword = /python3\sntlmv1\.py\s/ nocase ascii wide
                        $string21_NetNTLMtoSilverTicket_offensive_tool_keyword = /Responder\.py\s\-I\s/ nocase ascii wide
                        $string22_NetNTLMtoSilverTicket_offensive_tool_keyword = /rpcdump\.py\s.{0,100}\s\|\sgrep\sMS\-RPRN/ nocase ascii wide
                        $string23_NetNTLMtoSilverTicket_offensive_tool_keyword = /SpoolSample\.exe\s.{0,100}\s/ nocase ascii wide
                        $string24_NetNTLMtoSilverTicket_offensive_tool_keyword = /ticketer\.py\s\-nthash\s/ nocase ascii wide
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