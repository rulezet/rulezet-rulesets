rule rule_hiphp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hiphp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hiphp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hiphp_offensive_tool_keyword = /\shiphp\-cli\.sh/ nocase ascii wide
                        $string2_hiphp_offensive_tool_keyword = /\shiphp\-desktop\.sh/ nocase ascii wide
                        $string3_hiphp_offensive_tool_keyword = " -i -t hiphp:latest" nocase ascii wide
                        $string4_hiphp_offensive_tool_keyword = /\/hiphp\.git/ nocase ascii wide
                        $string5_hiphp_offensive_tool_keyword = /\/hiphp\-cli\.sh/ nocase ascii wide
                        $string6_hiphp_offensive_tool_keyword = /\/hiphp\-desktop\.sh/ nocase ascii wide
                        $string7_hiphp_offensive_tool_keyword = "/hiphp-main" nocase ascii wide
                        $string8_hiphp_offensive_tool_keyword = /\\hiphp\-cli\.sh/ nocase ascii wide
                        $string9_hiphp_offensive_tool_keyword = /\\hiphp\-desktop\.sh/ nocase ascii wide
                        $string10_hiphp_offensive_tool_keyword = "docker build -t hiphp:latest" nocase ascii wide
                        $string11_hiphp_offensive_tool_keyword = /docker.{0,100}\/hiphp\:latest/ nocase ascii wide
                        $string12_hiphp_offensive_tool_keyword = "e7370f93d1d0cde622a1f8e1c04877d8463912d04d973331ad4851f04de6915a" nocase ascii wide
                        $string13_hiphp_offensive_tool_keyword = "from hiphp import " nocase ascii wide
                        $string14_hiphp_offensive_tool_keyword = /hiphp\s.{0,100}\-\-url/ nocase ascii wide
                        $string15_hiphp_offensive_tool_keyword = /hiphp\.hiphplinkextractor/ nocase ascii wide
                        $string16_hiphp_offensive_tool_keyword = /hiphp\.hiphpversion/ nocase ascii wide
                        $string17_hiphp_offensive_tool_keyword = /hiphp\-0\.3\.4\.deb/ nocase ascii wide
                        $string18_hiphp_offensive_tool_keyword = /hiphp\-0\.3\.5\.deb/ nocase ascii wide
                        $string19_hiphp_offensive_tool_keyword = /hiphp\-0\.3\.6\.deb/ nocase ascii wide
                        $string20_hiphp_offensive_tool_keyword = /hiphp\-1\..{0,100}\..{0,100}\.deb/ nocase ascii wide
                        $string21_hiphp_offensive_tool_keyword = /hiphp\-cli\.bat/ nocase ascii wide
                        $string22_hiphp_offensive_tool_keyword = /hiphp\-desktop\.bat/ nocase ascii wide
                        $string23_hiphp_offensive_tool_keyword = /hiphp\-termux\.sh/ nocase ascii wide
                        $string24_hiphp_offensive_tool_keyword = /hiphp\-tk\.bat/ nocase ascii wide
                        $string25_hiphp_offensive_tool_keyword = "Killing ngrok tunnel" nocase ascii wide
                        $string26_hiphp_offensive_tool_keyword = "pip install hiphp" nocase ascii wide
                        $string27_hiphp_offensive_tool_keyword = /python\smain\.py\s\-\-KEY\=.{0,100}\s\-\-URL\=.{0,100}127\.0\.0\.1/ nocase ascii wide
                        $string28_hiphp_offensive_tool_keyword = /run\-hiphp\-tk\.sh/ nocase ascii wide
                        $string29_hiphp_offensive_tool_keyword = /share\/hiphp\.py/ nocase ascii wide
                        $string30_hiphp_offensive_tool_keyword = "yasserbdj96/hiphp" nocase ascii wide
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