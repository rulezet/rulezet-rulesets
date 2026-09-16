rule Proxifier
{
    meta:
        description = "Detection patterns for the tool 'Proxifier' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Proxifier"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " stop ProxifierDrv" nocase ascii wide
                        $string2 = /\/Proxifier\.app\/Contents\/MacOS\/Proxifier/ nocase ascii wide
                        $string3 = /\/Proxifier\.exe/ nocase ascii wide
                        $string4 = /\/Proxifier\/Proxifier\.app\// nocase ascii wide
                        $string5 = /\/ProxifierPE\.zip/ nocase ascii wide
                        $string6 = /\/ProxifierSetup\.exe/ nocase ascii wide
                        $string7 = /\\AppData\\Local\\Temp\\.{0,100}\\Proxifier\sPE\\/ nocase ascii wide
                        $string8 = /\\AppData\\Local\\Temp\\Proxifier\sPE\\/ nocase ascii wide
                        $string9 = /\\Proxifier\sService\sManager\.lnk/ nocase ascii wide
                        $string10 = /\\Proxifier\.exe/ nocase ascii wide
                        $string11 = /\\Proxifier\.lnk/ nocase ascii wide
                        $string12 = /\\ProxifierDrv\.sys/ nocase ascii wide
                        $string13 = /\\ProxifierPE\.zip/ nocase ascii wide
                        $string14 = /\\ProxifierSetup\.exe/ nocase ascii wide
                        $string15 = /\\ProxifierSetup\.tmp/ nocase ascii wide
                        $string16 = /\\ProxifierShellExt\.dll/ nocase ascii wide
                        $string17 = /\\ProxyChecker\.exe/ nocase ascii wide
                        $string18 = /\\SOFTWARE\\WOW6432Node\\Microsoft\\Tracing\\Proxifier_/ nocase ascii wide
                        $string19 = /\\Start\sMenu\\Programs\\Proxifier/ nocase ascii wide
                        $string20 = ">Proxifier Setup<" nocase ascii wide
                        $string21 = /com\.initex\.proxifier\.v3\.macos/ nocase ascii wide
                        $string22 = /http\:\/\/www\.proxifier\.com\/distr\/last_versions\/ProxifierMac/ nocase ascii wide
                        $string23 = /http\:\/\/www\.proxifier\.com\/distr\/last_versions\/ProxifierPortable/ nocase ascii wide
                        $string24 = /Program\sFiles\s\(x86\)\\Proxifier/ nocase ascii wide
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