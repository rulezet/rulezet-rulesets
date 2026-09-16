rule rule__3proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '3proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "3proxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1__3proxy_greyware_tool_keyword = /\/3proxy\-.{0,100}\.deb/ nocase ascii wide
                        $string2__3proxy_greyware_tool_keyword = /\/3proxy\-.{0,100}\.rpm/ nocase ascii wide
                        $string3__3proxy_greyware_tool_keyword = /\/3proxy\-.{0,100}\.zip/ nocase ascii wide
                        $string4__3proxy_greyware_tool_keyword = /\/3proxy\.exe/ nocase ascii wide
                        $string5__3proxy_greyware_tool_keyword = /\/3proxy\.git/ nocase ascii wide
                        $string6__3proxy_greyware_tool_keyword = /\/3proxy\.log/
                        $string7__3proxy_greyware_tool_keyword = "/etc/3proxy/conf"
                        $string8__3proxy_greyware_tool_keyword = /\\3proxy\-.{0,100}\.deb/ nocase ascii wide
                        $string9__3proxy_greyware_tool_keyword = /\\3proxy\-.{0,100}\.rpm/ nocase ascii wide
                        $string10__3proxy_greyware_tool_keyword = /\\3proxy\-.{0,100}\.zip/ nocase ascii wide
                        $string11__3proxy_greyware_tool_keyword = /\\3proxy\.cfg/ nocase ascii wide
                        $string12__3proxy_greyware_tool_keyword = /\\3proxy\.exe/ nocase ascii wide
                        $string13__3proxy_greyware_tool_keyword = /\\3proxy\.key/ nocase ascii wide
                        $string14__3proxy_greyware_tool_keyword = /\\3proxy\.log/ nocase ascii wide
                        $string15__3proxy_greyware_tool_keyword = /\\bin\\3proxy/ nocase ascii wide
                        $string16__3proxy_greyware_tool_keyword = /128s3proxy\.key\\"/ nocase ascii wide
                        $string17__3proxy_greyware_tool_keyword = "3proxy --install" nocase ascii wide
                        $string18__3proxy_greyware_tool_keyword = "3proxy --remove" nocase ascii wide
                        $string19__3proxy_greyware_tool_keyword = "3proxy tiny proxy server" nocase ascii wide
                        $string20__3proxy_greyware_tool_keyword = "3proxy Windows Authentication plugin" nocase ascii wide
                        $string21__3proxy_greyware_tool_keyword = /3proxy\.exe\s\-\-/ nocase ascii wide
                        $string22__3proxy_greyware_tool_keyword = /3proxy\.service/ nocase ascii wide
                        $string23__3proxy_greyware_tool_keyword = "3proxy/3proxy" nocase ascii wide
                        $string24__3proxy_greyware_tool_keyword = /3proxy\@3proxy\.org/ nocase ascii wide
                        $string25__3proxy_greyware_tool_keyword = /add3proxyuser\.sh/ nocase ascii wide
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