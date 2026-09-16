rule rule_ivy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ivy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ivy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-O\s.{0,1000}\.png\s\-stageless/ nocase ascii wide
                        $string2_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.hta\s\-url\shttp\:.{0,1000}\s\-delivery\shta\s\-stageless/ nocase ascii wide
                        $string3_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.js\s\-url\shttp.{0,1000}\s\-delivery\sbits\s\-stageless/ nocase ascii wide
                        $string4_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.txt\s\-url\shttp.{0,1000}\s\-delivery\smacro\s\-stageless/ nocase ascii wide
                        $string5_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.xsl\s\-url\shttp.{0,1000}\s\-delivery\sxsl\s\-stageless/ nocase ascii wide
                        $string6_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,1000}\.c\s\-Ix86\s.{0,1000}\.c\s\-P\sLocal\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string7_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,1000}\.vba\s\-Ix86\s.{0,1000}\.vba\s\-P\sInject\s\-O\s/ nocase ascii wide
                        $string8_ivy_offensive_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string9_ivy_offensive_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-process64\s.{0,1000}\.exe\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string10_ivy_offensive_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-unhook\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string11_ivy_offensive_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string12_ivy_offensive_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-unhook\s\-O\s.{0,1000}\.js/ nocase ascii wide
                        $string13_ivy_offensive_tool_keyword = /\.\/Ivy\s\-/
                        $string14_ivy_offensive_tool_keyword = "/Ivy/Cryptor" nocase ascii wide
                        $string15_ivy_offensive_tool_keyword = "/Ivy/Loader/" nocase ascii wide
                        $string16_ivy_offensive_tool_keyword = /\\Ivy\\Cryptor/ nocase ascii wide
                        $string17_ivy_offensive_tool_keyword = /\\Ivy\\Loader\\/ nocase ascii wide
                        $string18_ivy_offensive_tool_keyword = "7267a9321dd7ab890af5892975e257f89b2e53c70216c3708be9b0418e6b470e" nocase ascii wide
                        $string19_ivy_offensive_tool_keyword = /go\sbuild\sIvy\.go/ nocase ascii wide
                        $string20_ivy_offensive_tool_keyword = /Ivy_1.{0,1000}_darwin_amd64/
                        $string21_ivy_offensive_tool_keyword = /Ivy_1.{0,1000}_linux_amd64/
                        $string22_ivy_offensive_tool_keyword = /Ivy_1.{0,1000}_windows_amd64\.exe/ nocase ascii wide
                        $string23_ivy_offensive_tool_keyword = /Ivy\-main\.zip/ nocase ascii wide
                        $string24_ivy_offensive_tool_keyword = /optiv\/Ivy\.git/ nocase ascii wide
                        $string25_ivy_offensive_tool_keyword = "Tylous/Ivy" nocase ascii wide

    condition:
        any of them
}