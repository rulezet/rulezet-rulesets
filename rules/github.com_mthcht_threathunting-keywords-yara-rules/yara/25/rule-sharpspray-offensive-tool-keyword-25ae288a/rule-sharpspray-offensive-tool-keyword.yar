rule rule_SharpSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSpray_offensive_tool_keyword = /\s\-o\ssprayed\.txt/ nocase ascii wide
                        $string2_SharpSpray_offensive_tool_keyword = /\ssharpspray\.exe/ nocase ascii wide
                        $string3_SharpSpray_offensive_tool_keyword = " -x -z --get-users-list" nocase ascii wide
                        $string4_SharpSpray_offensive_tool_keyword = /\s\-x\s\-z\s\-s\s3\s\-j\s1\s\-u\s.{0,1000}\.txt/ nocase ascii wide
                        $string5_SharpSpray_offensive_tool_keyword = /\.exe\s\-\-get\-users\-list\s\>\s/ nocase ascii wide
                        $string6_SharpSpray_offensive_tool_keyword = /\/sharpspray\.exe/ nocase ascii wide
                        $string7_SharpSpray_offensive_tool_keyword = /\/SharpSpray\.git/ nocase ascii wide
                        $string8_SharpSpray_offensive_tool_keyword = /\/SharpSpray\-1\.1\.zip/ nocase ascii wide
                        $string9_SharpSpray_offensive_tool_keyword = /\\SharpSpray\.csproj/ nocase ascii wide
                        $string10_SharpSpray_offensive_tool_keyword = /\\sharpspray\.exe/ nocase ascii wide
                        $string11_SharpSpray_offensive_tool_keyword = /\\SharpSpray\.sln/ nocase ascii wide
                        $string12_SharpSpray_offensive_tool_keyword = /\\SharpSpray\\/ nocase ascii wide
                        $string13_SharpSpray_offensive_tool_keyword = /\\SharpSpray\-1\.1\.zip/ nocase ascii wide
                        $string14_SharpSpray_offensive_tool_keyword = "29CFAA16-9277-4EFB-9E91-A7D11225160B" nocase ascii wide
                        $string15_SharpSpray_offensive_tool_keyword = "9a30590136ad955b56d367ca00f3d9feb50d4a3fb1d643fc8e3bb3cbcfd1dfa1" nocase ascii wide
                        $string16_SharpSpray_offensive_tool_keyword = /DomainPasswordSpray\.ps1/ nocase ascii wide
                        $string17_SharpSpray_offensive_tool_keyword = "iomoath/SharpSpray" nocase ascii wide
                        $string18_SharpSpray_offensive_tool_keyword = "SharpSpray" nocase ascii wide
                        $string19_SharpSpray_offensive_tool_keyword = /SharpSpray\\Program\.cs/ nocase ascii wide

    condition:
        any of them
}