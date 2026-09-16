rule yakit
{
    meta:
        description = "Detection patterns for the tool 'yakit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "yakit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sset\-proxy\.ps1/ nocase ascii wide
                        $string2 = "\"http://mitm\"" nocase ascii wide
                        $string3 = "/MITMPluginLogViewer" nocase ascii wide
                        $string4 = "/MITMServerHijacking" nocase ascii wide
                        $string5 = /\/set\-proxy\.ps1/ nocase ascii wide
                        $string6 = /\/yak_darwin_amd64\.zip/
                        $string7 = /\/yak_linux_amd64\.zip/
                        $string8 = /\/yak_windows_amd64\.zip/ nocase ascii wide
                        $string9 = /\?\?\sMITM\s\?\?\?\?/ nocase ascii wide
                        $string10 = /\\default\-yakit\.db/ nocase ascii wide
                        $string11 = /\\set\-proxy\.ps1/ nocase ascii wide
                        $string12 = /\\System32\\yak\.exe/ nocase ascii wide
                        $string13 = /\\yak\.exe/ nocase ascii wide
                        $string14 = "MITMServerHijacking/MITMPluginLocalList" nocase ascii wide
                        $string15 = "pwd86u1qwZ9PWevKqm1A3yAw==" nocase ascii wide
                        $string16 = "PwDaBjJzgufjES89Rs4Lpq63O300R/kOz30WCLo6BxxX6QVEilwSlpClnG5cZaikTA==" nocase ascii wide
                        $string17 = "pWDkVEtllTAK5h6cnhxNxDA==" nocase ascii wide
                        $string18 = /Yakit\-.{0,100}\-windows\-amd64\.exe/ nocase ascii wide
                        $string19 = /Yakit\/1\.0\.0/ nocase ascii wide
                        $string20 = "YAKIT_MITM" nocase ascii wide
                        $string21 = /yakit\-remote\.json/ nocase ascii wide
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