rule rule_Shwmae_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Shwmae' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shwmae"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Shwmae_offensive_tool_keyword = "\"author\": \"@_EthicalChaos_\"" nocase ascii wide
                        $string2_Shwmae_offensive_tool_keyword = /\.exe\sdump\s\-\-key\-name\s/ nocase ascii wide
                        $string3_Shwmae_offensive_tool_keyword = /\/Shwmae\.exe/ nocase ascii wide
                        $string4_Shwmae_offensive_tool_keyword = /\/Shwmae\.git/ nocase ascii wide
                        $string5_Shwmae_offensive_tool_keyword = "/shwmae/keys" nocase ascii wide
                        $string6_Shwmae_offensive_tool_keyword = /\/webauthn\-inject\.js/ nocase ascii wide
                        $string7_Shwmae_offensive_tool_keyword = /\[\!\]\sFailed\sto\sget\sprivileges\swhen\strying\sto\sgain\sSYSTEM/ nocase ascii wide
                        $string8_Shwmae_offensive_tool_keyword = /\[\+\]\sDecrypted\sSYSTEM\svault\spolicy/ nocase ascii wide
                        $string9_Shwmae_offensive_tool_keyword = /\[\+\]\sSuccessfully\sdecrypted\sNGC\skey\sset\sfrom\sprotector\stype\s/ nocase ascii wide
                        $string10_Shwmae_offensive_tool_keyword = /\\Shwmae\.exe/ nocase ascii wide
                        $string11_Shwmae_offensive_tool_keyword = /\\webauthn\-inject\.js/ nocase ascii wide
                        $string12_Shwmae_offensive_tool_keyword = "1bb41d5d6d3c883be23682ec1d94ee3317c0ab8d5fa2bee3712a5f33c0d6960b" nocase ascii wide
                        $string13_Shwmae_offensive_tool_keyword = "228eb663a1c8bfc0f6a05ba522038844c762319961b07e5b623dcfa8e30ce5fa" nocase ascii wide
                        $string14_Shwmae_offensive_tool_keyword = "5D3EF551-3D1F-468E-A75B-764F436D577D" nocase ascii wide
                        $string15_Shwmae_offensive_tool_keyword = "c97e849bf283c760811373be29c588adc6ad820d7695a7552e87be693bea0ee6" nocase ascii wide
                        $string16_Shwmae_offensive_tool_keyword = "CCob/Shwmae" nocase ascii wide
                        $string17_Shwmae_offensive_tool_keyword = "Forwards WebAuthn assertion requests to a compromised host running the Shwmae Windows Hello abuse tool" nocase ascii wide
                        $string18_Shwmae_offensive_tool_keyword = "ijacbjjjpmhencpkoghphdgbooifplmn" nocase ascii wide
                        $string19_Shwmae_offensive_tool_keyword = "Shwmae dump " nocase ascii wide
                        $string20_Shwmae_offensive_tool_keyword = "Shwmae enum " nocase ascii wide
                        $string21_Shwmae_offensive_tool_keyword = "Shwmae prt " nocase ascii wide
                        $string22_Shwmae_offensive_tool_keyword = "Shwmae prt " nocase ascii wide
                        $string23_Shwmae_offensive_tool_keyword = "Shwmae sign " nocase ascii wide
                        $string24_Shwmae_offensive_tool_keyword = "Shwmae webauthn " nocase ascii wide
                        $string25_Shwmae_offensive_tool_keyword = "Shwmae webauthn" nocase ascii wide
                        $string26_Shwmae_offensive_tool_keyword = /Shwmae\.exe\ssign/ nocase ascii wide
                        $string27_Shwmae_offensive_tool_keyword = "WebAuthn proxy running" nocase ascii wide
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