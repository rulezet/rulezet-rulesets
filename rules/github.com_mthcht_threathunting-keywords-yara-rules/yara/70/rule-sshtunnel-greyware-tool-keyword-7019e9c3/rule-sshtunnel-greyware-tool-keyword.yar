rule rule_sshtunnel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sshtunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshtunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_sshtunnel_greyware_tool_keyword = " install -c conda-forge sshtunnel" nocase ascii wide
                        $string2_sshtunnel_greyware_tool_keyword = " -m sshtunnel " nocase ascii wide
                        $string3_sshtunnel_greyware_tool_keyword = /\ssshtunnel\.py/ nocase ascii wide
                        $string4_sshtunnel_greyware_tool_keyword = /\sSSHTunnelForwarder\(/ nocase ascii wide
                        $string5_sshtunnel_greyware_tool_keyword = "/sshtunnel -"
                        $string6_sshtunnel_greyware_tool_keyword = /\/sshtunnel\.git/ nocase ascii wide
                        $string7_sshtunnel_greyware_tool_keyword = /\/sshtunnel\.py/ nocase ascii wide
                        $string8_sshtunnel_greyware_tool_keyword = "/sshtunnel/tarball/" nocase ascii wide
                        $string9_sshtunnel_greyware_tool_keyword = "/sshtunnel/zipball/" nocase ascii wide
                        $string10_sshtunnel_greyware_tool_keyword = /\\sshtunnel\.py/ nocase ascii wide
                        $string11_sshtunnel_greyware_tool_keyword = "c89b4490de04897b1c16e5dae1c10ef10e60c56294bd4ca45d1669f5dcb6f9e3" nocase ascii wide
                        $string12_sshtunnel_greyware_tool_keyword = /Creating\sSSHTunnelForwarder.{0,100}paramiko/ nocase ascii wide
                        $string13_sshtunnel_greyware_tool_keyword = "easy_install sshtunnel" nocase ascii wide
                        $string14_sshtunnel_greyware_tool_keyword = "from sshtunnel import " nocase ascii wide
                        $string15_sshtunnel_greyware_tool_keyword = "from sshtunnel import SSHTunnelForwarder" nocase ascii wide
                        $string16_sshtunnel_greyware_tool_keyword = "import sshtunnel" nocase ascii wide
                        $string17_sshtunnel_greyware_tool_keyword = "pahaz/sshtunnel" nocase ascii wide
                        $string18_sshtunnel_greyware_tool_keyword = "pip install sshtunnel" nocase ascii wide
                        $string19_sshtunnel_greyware_tool_keyword = /sshtunnel\.readthedocs\.io/ nocase ascii wide
                        $string20_sshtunnel_greyware_tool_keyword = /sshtunnel\.readthedocs\.org/ nocase ascii wide
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