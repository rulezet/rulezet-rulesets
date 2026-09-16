rule rule_clickjack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'clickjack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "clickjack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_clickjack_offensive_tool_keyword = /\s\-\-CollectLinks\s\-\-apitoken\s.{0,100}\s\-\-outfile\s/ nocase ascii wide
                        $string2_clickjack_offensive_tool_keyword = /\s\-\-Inject\s\-\-stub\s.{0,100}\.dll.{0,100}\s\-\-app\s/ nocase ascii wide
                        $string3_clickjack_offensive_tool_keyword = /\/ClickJack\.exe/ nocase ascii wide
                        $string4_clickjack_offensive_tool_keyword = /\[\!\]\sThis\sapplication\scan\snot\sbe\sinjected/ nocase ascii wide
                        $string5_clickjack_offensive_tool_keyword = /\[\+\]\sThis\sapplication\sis\sinjectable\!/ nocase ascii wide
                        $string6_clickjack_offensive_tool_keyword = /\\ClickJack\.csproj/ nocase ascii wide
                        $string7_clickjack_offensive_tool_keyword = /\\ClickJack\.exe/ nocase ascii wide
                        $string8_clickjack_offensive_tool_keyword = "02FAF312-BF2A-466B-8AD2-1339A31C303B" nocase ascii wide
                        $string9_clickjack_offensive_tool_keyword = "40e8b756d0f996d7127ffc76d3fb122dd014455bc6b0c007e6d5d77e5bb6211b" nocase ascii wide
                        $string10_clickjack_offensive_tool_keyword = "88f333f2f21ca05e44a91c376022997c2bbec79b9d9982d59ee6d38183df86f3" nocase ascii wide
                        $string11_clickjack_offensive_tool_keyword = /InjectApp\.InfectClickonceApp\(/ nocase ascii wide
                        $string12_clickjack_offensive_tool_keyword = /using\sClickJack\.Extensions/ nocase ascii wide
                        $string13_clickjack_offensive_tool_keyword = /using\sClickJack\.Modules/ nocase ascii wide
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