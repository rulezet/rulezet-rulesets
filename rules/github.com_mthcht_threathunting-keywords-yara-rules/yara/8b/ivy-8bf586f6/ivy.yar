rule ivy
{
    meta:
        description = "Detection patterns for the tool 'ivy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ivy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-O\s.{0,1000}\.png\s\-stageless/ nocase ascii wide
                        $string2 = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.hta\s\-url\shttp\:.{0,1000}\s\-delivery\shta\s\-stageless/ nocase ascii wide
                        $string3 = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.js\s\-url\shttp.{0,1000}\s\-delivery\sbits\s\-stageless/ nocase ascii wide
                        $string4 = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.txt\s\-url\shttp.{0,1000}\s\-delivery\smacro\s\-stageless/ nocase ascii wide
                        $string5 = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.xsl\s\-url\shttp.{0,1000}\s\-delivery\sxsl\s\-stageless/ nocase ascii wide
                        $string6 = /\s\-Ix64\s.{0,1000}\.c\s\-Ix86\s.{0,1000}\.c\s\-P\sLocal\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string7 = /\s\-Ix64\s.{0,1000}\.vba\s\-Ix86\s.{0,1000}\.vba\s\-P\sInject\s\-O\s/ nocase ascii wide
                        $string8 = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string9 = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-process64\s.{0,1000}\.exe\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string10 = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-unhook\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string11 = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string12 = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-unhook\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string13 = /\.\/Ivy\s\-/
                        $string14 = "/Ivy/Cryptor" nocase ascii wide
                        $string15 = "/Ivy/Loader/" nocase ascii wide
                        $string16 = /\\Ivy\\Cryptor/ nocase ascii wide
                        $string17 = /\\Ivy\\Loader\\/ nocase ascii wide
                        $string18 = "7267a9321dd7ab890af5892975e257f89b2e53c70216c3708be9b0418e6b470e" nocase ascii wide
                        $string19 = /go\sbuild\sIvy\.go/ nocase ascii wide
                        $string20 = /Ivy_1.{0,1000}_darwin_amd64/
                        $string21 = /Ivy_1.{0,1000}_linux_amd64/
                        $string22 = /Ivy_1.{0,1000}_windows_amd64\.exe/ nocase ascii wide
                        $string23 = /Ivy\-main\.zip/ nocase ascii wide
                        $string24 = /optiv\/Ivy\.git/ nocase ascii wide
                        $string25 = "Tylous/Ivy" nocase ascii wide

    condition:
        any of them
}