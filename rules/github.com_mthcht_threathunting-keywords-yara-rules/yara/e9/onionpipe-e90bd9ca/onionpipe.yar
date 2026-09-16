rule onionpipe
{
    meta:
        description = "Detection patterns for the tool 'onionpipe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onionpipe"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\stor\sdeb\.torproject\.org\-keyring/ nocase ascii wide
                        $string2 = /\.onion\:31337/ nocase ascii wide
                        $string3 = /\.onion\:8000/ nocase ascii wide
                        $string4 = /\.onion\:81/ nocase ascii wide
                        $string5 = /\/onionpipe\.git/ nocase ascii wide
                        $string6 = "/onionpipe/releases/latest" nocase ascii wide
                        $string7 = "/onionpipe:main"
                        $string8 = "/usr/share/keyrings/tor-archive-keyring"
                        $string9 = /build_onionpipe\.bash/
                        $string10 = /build_tor_darwin\.bash/
                        $string11 = /build_tor_debian\.bash/
                        $string12 = "cmars/onionpipe" nocase ascii wide
                        $string13 = /dsbqrprgkqqifztta6h3w7i2htjhnq7d3qkh3c7gvc35e66rrcv66did\.onion/ nocase ascii wide
                        $string14 = "failed to shut down Tor -- possible bug in bine" nocase ascii wide
                        $string15 = "make onionpipe" nocase ascii wide
                        $string16 = "onionpipe --" nocase ascii wide
                        $string17 = /onionpipe\s.{0,100}\.onion\:/ nocase ascii wide
                        $string18 = /onionpipe\s.{0,100}\:.{0,100}\~/ nocase ascii wide
                        $string19 = "onionpipe /run/" nocase ascii wide
                        $string20 = "onionpipe 8000" nocase ascii wide
                        $string21 = "onionpipe client new " nocase ascii wide
                        $string22 = "onionpipe/secrets" nocase ascii wide
                        $string23 = "onionpipe/tor" nocase ascii wide
                        $string24 = "onionpipe-darwin-amd64-static"
                        $string25 = "onionpipe-linux-amd64-static"
                        $string26 = /sd6aq2r6jvuoeisrudq7jbqufjh6nck5buuzjmgalicgwrobgfj4lkqd\.onion/ nocase ascii wide
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