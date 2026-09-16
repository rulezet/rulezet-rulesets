rule Shwmae
{
    meta:
        description = "Detection patterns for the tool 'Shwmae' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shwmae"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "\"author\": \"@_EthicalChaos_\"" nocase ascii wide
                        $string2 = /\.exe\sdump\s\-\-key\-name\s/ nocase ascii wide
                        $string3 = /\/Shwmae\.exe/ nocase ascii wide
                        $string4 = /\/Shwmae\.git/ nocase ascii wide
                        $string5 = "/shwmae/keys" nocase ascii wide
                        $string6 = /\/webauthn\-inject\.js/ nocase ascii wide
                        $string7 = /\[\!\]\sFailed\sto\sget\sprivileges\swhen\strying\sto\sgain\sSYSTEM/ nocase ascii wide
                        $string8 = /\[\+\]\sDecrypted\sSYSTEM\svault\spolicy/ nocase ascii wide
                        $string9 = /\[\+\]\sSuccessfully\sdecrypted\sNGC\skey\sset\sfrom\sprotector\stype\s/ nocase ascii wide
                        $string10 = /\\Shwmae\.exe/ nocase ascii wide
                        $string11 = /\\webauthn\-inject\.js/ nocase ascii wide
                        $string12 = "1bb41d5d6d3c883be23682ec1d94ee3317c0ab8d5fa2bee3712a5f33c0d6960b" nocase ascii wide
                        $string13 = "228eb663a1c8bfc0f6a05ba522038844c762319961b07e5b623dcfa8e30ce5fa" nocase ascii wide
                        $string14 = "5D3EF551-3D1F-468E-A75B-764F436D577D" nocase ascii wide
                        $string15 = "c97e849bf283c760811373be29c588adc6ad820d7695a7552e87be693bea0ee6" nocase ascii wide
                        $string16 = "CCob/Shwmae" nocase ascii wide
                        $string17 = "Forwards WebAuthn assertion requests to a compromised host running the Shwmae Windows Hello abuse tool" nocase ascii wide
                        $string18 = "ijacbjjjpmhencpkoghphdgbooifplmn" nocase ascii wide
                        $string19 = "Shwmae dump " nocase ascii wide
                        $string20 = "Shwmae enum " nocase ascii wide
                        $string21 = "Shwmae prt " nocase ascii wide
                        $string22 = "Shwmae prt " nocase ascii wide
                        $string23 = "Shwmae sign " nocase ascii wide
                        $string24 = "Shwmae webauthn " nocase ascii wide
                        $string25 = "Shwmae webauthn" nocase ascii wide
                        $string26 = /Shwmae\.exe\ssign/ nocase ascii wide
                        $string27 = "WebAuthn proxy running" nocase ascii wide
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