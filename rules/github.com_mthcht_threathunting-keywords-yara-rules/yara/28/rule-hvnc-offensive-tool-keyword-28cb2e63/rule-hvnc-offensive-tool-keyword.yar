rule rule_HVNC_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HVNC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HVNC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HVNC_offensive_tool_keyword = /\/HVNC\.git/ nocase ascii wide
                        $string2_HVNC_offensive_tool_keyword = /\\HiddenDesktop\.h/ nocase ascii wide
                        $string3_HVNC_offensive_tool_keyword = /\\hvnc\.exe/ nocase ascii wide
                        $string4_HVNC_offensive_tool_keyword = /\\HVNC\.sln/ nocase ascii wide
                        $string5_HVNC_offensive_tool_keyword = /\\HVNC\.vcxproj/ nocase ascii wide
                        $string6_HVNC_offensive_tool_keyword = /\\HVNC\-main\.zip/ nocase ascii wide
                        $string7_HVNC_offensive_tool_keyword = "095a6fc6a2c9647417df017fa70b182abcc68b97a8addd4e25cf302f6f2e98e4" nocase ascii wide
                        $string8_HVNC_offensive_tool_keyword = "3791fe80848940a320ef55ec49c9a23fffcb1b97977d0a6140df61efc6533829" nocase ascii wide
                        $string9_HVNC_offensive_tool_keyword = "5C3AD9AC-C62C-4AA8-BAE2-9AF920A652E3" nocase ascii wide
                        $string10_HVNC_offensive_tool_keyword = "6003ae86c0abcc19ae6c799724e679762ed37934ab6b5c3064f65988df64a242" nocase ascii wide
                        $string11_HVNC_offensive_tool_keyword = "69ad04521e133db1e34347ec9a6ecb8ea3f90272c77ce2471c3145ac33fad13b" nocase ascii wide
                        $string12_HVNC_offensive_tool_keyword = "FFE5AD77-8AF4-4A3F-8CE7-6BDC45565F07" nocase ascii wide
                        $string13_HVNC_offensive_tool_keyword = /g_hDesk\s\=\sFuncs\:\:pOpenDesktopA\(g_desktopName/ nocase ascii wide
                        $string14_HVNC_offensive_tool_keyword = /github\.com\/rossja\/TinyNuke/ nocase ascii wide
                        $string15_HVNC_offensive_tool_keyword = /HiddenDesktop\.cpp/ nocase ascii wide
                        $string16_HVNC_offensive_tool_keyword = /HiddenDesktop\.exe/ nocase ascii wide
                        $string17_HVNC_offensive_tool_keyword = "HiddenDesktop_ControlWindow" nocase ascii wide
                        $string18_HVNC_offensive_tool_keyword = /HVNC\s\-\sTinynuke\sClone\s\[Melted\@HF\]/ nocase ascii wide
                        $string19_HVNC_offensive_tool_keyword = "HVNC - Tinynuke Clone" nocase ascii wide
                        $string20_HVNC_offensive_tool_keyword = "'M', 'E', 'L', 'T', 'E', 'D', 0" nocase ascii wide
                        $string21_HVNC_offensive_tool_keyword = /melted\@xmpp\.jp/ nocase ascii wide
                        $string22_HVNC_offensive_tool_keyword = "Meltedd/HVNC" nocase ascii wide
                        $string23_HVNC_offensive_tool_keyword = "Starting HVNC Server" nocase ascii wide
                        $string24_HVNC_offensive_tool_keyword = /t\.me\/Melteddd/ nocase ascii wide

    condition:
        any of them
}