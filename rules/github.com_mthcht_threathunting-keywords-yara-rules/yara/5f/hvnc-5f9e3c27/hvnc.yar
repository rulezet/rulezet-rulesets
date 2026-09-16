rule HVNC
{
    meta:
        description = "Detection patterns for the tool 'HVNC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HVNC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/HVNC\.git/ nocase ascii wide
                        $string2 = /\\HiddenDesktop\.h/ nocase ascii wide
                        $string3 = /\\hvnc\.exe/ nocase ascii wide
                        $string4 = /\\HVNC\.sln/ nocase ascii wide
                        $string5 = /\\HVNC\.vcxproj/ nocase ascii wide
                        $string6 = /\\HVNC\-main\.zip/ nocase ascii wide
                        $string7 = "095a6fc6a2c9647417df017fa70b182abcc68b97a8addd4e25cf302f6f2e98e4" nocase ascii wide
                        $string8 = "3791fe80848940a320ef55ec49c9a23fffcb1b97977d0a6140df61efc6533829" nocase ascii wide
                        $string9 = "5C3AD9AC-C62C-4AA8-BAE2-9AF920A652E3" nocase ascii wide
                        $string10 = "6003ae86c0abcc19ae6c799724e679762ed37934ab6b5c3064f65988df64a242" nocase ascii wide
                        $string11 = "69ad04521e133db1e34347ec9a6ecb8ea3f90272c77ce2471c3145ac33fad13b" nocase ascii wide
                        $string12 = "FFE5AD77-8AF4-4A3F-8CE7-6BDC45565F07" nocase ascii wide
                        $string13 = /g_hDesk\s\=\sFuncs\:\:pOpenDesktopA\(g_desktopName/ nocase ascii wide
                        $string14 = /github\.com\/rossja\/TinyNuke/ nocase ascii wide
                        $string15 = /HiddenDesktop\.cpp/ nocase ascii wide
                        $string16 = /HiddenDesktop\.exe/ nocase ascii wide
                        $string17 = "HiddenDesktop_ControlWindow" nocase ascii wide
                        $string18 = /HVNC\s\-\sTinynuke\sClone\s\[Melted\@HF\]/ nocase ascii wide
                        $string19 = "HVNC - Tinynuke Clone" nocase ascii wide
                        $string20 = "'M', 'E', 'L', 'T', 'E', 'D', 0" nocase ascii wide
                        $string21 = /melted\@xmpp\.jp/ nocase ascii wide
                        $string22 = "Meltedd/HVNC" nocase ascii wide
                        $string23 = "Starting HVNC Server" nocase ascii wide
                        $string24 = /t\.me\/Melteddd/ nocase ascii wide

    condition:
        any of them
}