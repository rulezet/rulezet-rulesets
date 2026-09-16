rule rule_Azure_Storage_Explorer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Azure Storage Explorer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Azure Storage Explorer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Azure_Storage_Explorer_greyware_tool_keyword = /\/Microsoft\sAzure\sStorage\sExplorer\.app/ nocase ascii wide
                        $string2_Azure_Storage_Explorer_greyware_tool_keyword = /\/Microsoft\sAzure\sStorage\sExplorer\.zip/ nocase ascii wide
                        $string3_Azure_Storage_Explorer_greyware_tool_keyword = /\\Microsoft\sAzure\sStorage\sExplorer\.zip/ nocase ascii wide
                        $string4_Azure_Storage_Explorer_greyware_tool_keyword = ">Microsoft Azure Storage Explorer Setup<" nocase ascii wide
                        $string5_Azure_Storage_Explorer_greyware_tool_keyword = ">Microsoft Azure Storage Explorer<" nocase ascii wide
                        $string6_Azure_Storage_Explorer_greyware_tool_keyword = "036a9029e3b883ded8de9d9bdde3f63dd86d3403b7ed767b1efc3037c9d37bc4" nocase ascii wide
                        $string7_Azure_Storage_Explorer_greyware_tool_keyword = "7fa49a08d05a3616b5a24f52645d76c4496c37f5060a6bd4a648f534c4e85ae0" nocase ascii wide
                        $string8_Azure_Storage_Explorer_greyware_tool_keyword = "c798b2aedc7a74f0daf51eb216aae8cb48b45f208b0409916442b1d61d2ad2ef" nocase ascii wide
                        $string9_Azure_Storage_Explorer_greyware_tool_keyword = /com\.microsoft\.StorageExplorer/ nocase ascii wide
                        $string10_Azure_Storage_Explorer_greyware_tool_keyword = /Microsoft\sAzure\sStorage\sExplorer\.app\/Contents\// nocase ascii wide
                        $string11_Azure_Storage_Explorer_greyware_tool_keyword = /StorageExplorer\-linux\-x64\.tar\.gz/
                        $string12_Azure_Storage_Explorer_greyware_tool_keyword = /StorageExplorer\-windows\-x64\.exe/ nocase ascii wide
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