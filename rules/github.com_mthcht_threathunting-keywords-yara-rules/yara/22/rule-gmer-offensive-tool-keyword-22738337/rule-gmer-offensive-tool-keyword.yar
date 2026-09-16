rule rule_gmer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gmer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gmer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gmer_offensive_tool_keyword = /\/gmer\.exe/ nocase ascii wide
                        $string2_gmer_offensive_tool_keyword = /\/gmer64\.sys/
                        $string3_gmer_offensive_tool_keyword = /\\gmer\.exe/ nocase ascii wide
                        $string4_gmer_offensive_tool_keyword = /\\gmer64\.pdb/ nocase ascii wide
                        $string5_gmer_offensive_tool_keyword = /\\gmer64\.sys/ nocase ascii wide
                        $string6_gmer_offensive_tool_keyword = /\\Release\\gmer\.pdb/ nocase ascii wide
                        $string7_gmer_offensive_tool_keyword = /\>GMER\sDriver\shttp\:\/\/www\.gmer\.net\</ nocase ascii wide
                        $string8_gmer_offensive_tool_keyword = "18c909a2b8c5e16821d6ef908f56881aa0ecceeaccb5fa1e54995935fcfd12f7" nocase ascii wide
                        $string9_gmer_offensive_tool_keyword = "de3abde117d7eacbb638bc7d0151f929cf80a4bb5e5beb1e390839e96fc6722a" nocase ascii wide
                        $string10_gmer_offensive_tool_keyword = "e8a3e804a96c716a3e9b69195db6ffb0d33e2433af871e4d4e1eab3097237173" nocase ascii wide
                        $string11_gmer_offensive_tool_keyword = "e8a3e804a96c716a3e9b69195db6ffb0d33e2433af871e4d4e1eab3097237173" nocase ascii wide
                        $string12_gmer_offensive_tool_keyword = /http\:\/\/www\.gmer\.net\/\#files/ nocase ascii wide
                        $string13_gmer_offensive_tool_keyword = /http\:\/\/www2\.gmer\.net\/download/ nocase ascii wide
                        $string14_gmer_offensive_tool_keyword = /http\:\/\/www2\.gmer\.net\/gmer\.zip/ nocase ascii wide
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