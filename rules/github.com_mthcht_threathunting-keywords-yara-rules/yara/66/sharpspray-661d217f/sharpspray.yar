rule SharpSpray
{
    meta:
        description = "Detection patterns for the tool 'SharpSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-o\ssprayed\.txt/ nocase ascii wide
                        $string2 = /\ssharpspray\.exe/ nocase ascii wide
                        $string3 = " -x -z --get-users-list" nocase ascii wide
                        $string4 = /\s\-x\s\-z\s\-s\s3\s\-j\s1\s\-u\s.{0,1000}\.txt/ nocase ascii wide
                        $string5 = /\.exe\s\-\-get\-users\-list\s\>\s/ nocase ascii wide
                        $string6 = /\/sharpspray\.exe/ nocase ascii wide
                        $string7 = /\/SharpSpray\.git/ nocase ascii wide
                        $string8 = /\/SharpSpray\-1\.1\.zip/ nocase ascii wide
                        $string9 = /\\SharpSpray\.csproj/ nocase ascii wide
                        $string10 = /\\sharpspray\.exe/ nocase ascii wide
                        $string11 = /\\SharpSpray\.sln/ nocase ascii wide
                        $string12 = /\\SharpSpray\\/ nocase ascii wide
                        $string13 = /\\SharpSpray\-1\.1\.zip/ nocase ascii wide
                        $string14 = "29CFAA16-9277-4EFB-9E91-A7D11225160B" nocase ascii wide
                        $string15 = "9a30590136ad955b56d367ca00f3d9feb50d4a3fb1d643fc8e3bb3cbcfd1dfa1" nocase ascii wide
                        $string16 = /DomainPasswordSpray\.ps1/ nocase ascii wide
                        $string17 = "iomoath/SharpSpray" nocase ascii wide
                        $string18 = "SharpSpray" nocase ascii wide
                        $string19 = /SharpSpray\\Program\.cs/ nocase ascii wide

    condition:
        any of them
}