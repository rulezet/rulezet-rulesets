rule expose
{
    meta:
        description = "Detection patterns for the tool 'expose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "expose"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " /usr/local/bin/expose"
                        $string2 = /\/expose\/database\/expose\.db/ nocase ascii wide
                        $string3 = "/expose/raw/master/builds/expose" nocase ascii wide
                        $string4 = "/src/expose serve "
                        $string5 = "beyondcode/expose" nocase ascii wide
                        $string6 = "docker build -t expose " nocase ascii wide
                        $string7 = "docker run expose " nocase ascii wide
                        $string8 = "expose share http://" nocase ascii wide
                        $string9 = /exposeConfigPath\=\/src\/config\/expose\.php/ nocase ascii wide
                        $string10 = /\'host\'\s\=\>\s\'sharedwithexpose\.com\'/ nocase ascii wide
                        $string11 = /http\:\/\/127\.0\.0\.1\:4040\/api\/logs\// nocase ascii wide
                        $string12 = /https\:\/\/expose\.dev\/api\/servers/ nocase ascii wide
                        $string13 = /https\:\/\/expose\.dev\/register/ nocase ascii wide
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