rule rule_FileZilla_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FileZilla' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FileZilla"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_FileZilla_greyware_tool_keyword = /\/FileZilla_.{0,1000}_sponsored\-setup\.exe/ nocase ascii wide
                        $string2_FileZilla_greyware_tool_keyword = /\/FileZilla_Server_.{0,1000}\.deb/ nocase ascii wide
                        $string3_FileZilla_greyware_tool_keyword = /\\FileZilla_.{0,1000}_sponsored\-setup\.exe/ nocase ascii wide
                        $string4_FileZilla_greyware_tool_keyword = /\\FILEZILLA_.{0,1000}_WIN64_SPONSO\-.{0,1000}\.pf/ nocase ascii wide
                        $string5_FileZilla_greyware_tool_keyword = /\\FileZilla_.{0,1000}\-setup\.exe/ nocase ascii wide
                        $string6_FileZilla_greyware_tool_keyword = /\\FileZilla_Server_/ nocase ascii wide
                        $string7_FileZilla_greyware_tool_keyword = /\\Program\sFiles\\FileZilla\sFTP\sClient\\/ nocase ascii wide
                        $string8_FileZilla_greyware_tool_keyword = /\\Program\sFiles\\FileZilla\sServer/ nocase ascii wide
                        $string9_FileZilla_greyware_tool_keyword = /\\Software\\WOW6432Node\\FileZilla\sClient/ nocase ascii wide
                        $string10_FileZilla_greyware_tool_keyword = ">FileZilla FTP Client<" nocase ascii wide
                        $string11_FileZilla_greyware_tool_keyword = ">FileZilla Server<" nocase ascii wide
                        $string12_FileZilla_greyware_tool_keyword = /download\.filezilla\-project\.org/ nocase ascii wide
                        $string13_FileZilla_greyware_tool_keyword = /Software\\FileZilla/ nocase ascii wide
                        $string14_FileZilla_greyware_tool_keyword = "Win32/FileZilla_BundleInstaller" nocase ascii wide

    condition:
        any of them
}