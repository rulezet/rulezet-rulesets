rule rule_DynastyPersist_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DynastyPersist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DynastyPersist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DynastyPersist_offensive_tool_keyword = /\sdynasty\.sh/
                        $string2_DynastyPersist_offensive_tool_keyword = /\srce\.php\s\/var/
                        $string3_DynastyPersist_offensive_tool_keyword = /\.\/dynasty\.sh/
                        $string4_DynastyPersist_offensive_tool_keyword = /\/DynastyPersist\.git/
                        $string5_DynastyPersist_offensive_tool_keyword = /\/DynastyPersist\/src\/.{0,1000}\.sh/
                        $string6_DynastyPersist_offensive_tool_keyword = /\/var\/tmp\/\.memory\/diamorphine\.c/
                        $string7_DynastyPersist_offensive_tool_keyword = /\/var\/tmp\/\.memory\/diamorphine\.h/
                        $string8_DynastyPersist_offensive_tool_keyword = "/var/www/html/dynasty_rce"
                        $string9_DynastyPersist_offensive_tool_keyword = /\[\+\]\s\-\sBashrc\spersistence\sadded\!/
                        $string10_DynastyPersist_offensive_tool_keyword = /\[\+\]\s\-\sConfiguring\s\~\/\.bashrc\sfor\spersistence\s\.\.\.\s/
                        $string11_DynastyPersist_offensive_tool_keyword = /\[\+\]\s\-\sLinux\sheader\s\/\sMessage\sOf\sThe\sDay\sPersistence/
                        $string12_DynastyPersist_offensive_tool_keyword = /\[\+\]\s\-\sRootkit\sConfiguration/
                        $string13_DynastyPersist_offensive_tool_keyword = /\[\+\]\s\-\sRootkit\sconfigured\ssuccessfully/
                        $string14_DynastyPersist_offensive_tool_keyword = /\[\+\]\s\-\sSetting\sup\scronjobs\sfor\spersistence\s\.\.\.\s/
                        $string15_DynastyPersist_offensive_tool_keyword = /\[\+\]\s\-\sSystemd\sRoot\sLevel\sService\ssuccessfully\sconfigued\!/
                        $string16_DynastyPersist_offensive_tool_keyword = /\[\+\]\sSuccess\!\sLD_PRELOAD\shas\sbeen\sadded\!/
                        $string17_DynastyPersist_offensive_tool_keyword = /\\DynastyPersist\\src\\.{0,1000}\.sh/
                        $string18_DynastyPersist_offensive_tool_keyword = "<title>Dynasty Persist</title>"
                        $string19_DynastyPersist_offensive_tool_keyword = "D Y N A S T Y  - P E R S I S T"
                        $string20_DynastyPersist_offensive_tool_keyword = /dynasty_rce\/rce\.php/
                        $string21_DynastyPersist_offensive_tool_keyword = /DynastyPersist\-main\.zip/
                        $string22_DynastyPersist_offensive_tool_keyword = /echo\s\\"Nothing\sto\ssee\shere\s\.\.\.\s\\"\s\>\s\/var\/log\/kern\.log/
                        $string23_DynastyPersist_offensive_tool_keyword = /echo\s\'alias\scat\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'\'\s\>\>\s.{0,1000}\/\.bashrc.{0,1000}\s/
                        $string24_DynastyPersist_offensive_tool_keyword = /echo\s\'find\scat\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'\'\s\>\>\s.{0,1000}\/\.bashrc.{0,1000}\s/
                        $string25_DynastyPersist_offensive_tool_keyword = "ExecStartPre present! ExecStartPre was modified!"
                        $string26_DynastyPersist_offensive_tool_keyword = /https\:\/\/github\.com\/m0nad\/Diamorphine/
                        $string27_DynastyPersist_offensive_tool_keyword = "LDPreloadPrivesc"
                        $string28_DynastyPersist_offensive_tool_keyword = /Made\sby\:\s\@Trevohack\s\|\s\@opabravo\s\|\s\@matheuz/
                        $string29_DynastyPersist_offensive_tool_keyword = /Modified\sby\:\sTrevohack\saka\s.{0,1000}SpaceShuttleIO/
                        $string30_DynastyPersist_offensive_tool_keyword = /php\s\-S\s0\.0\.0\.0\:9056\s\&/
                        $string31_DynastyPersist_offensive_tool_keyword = /pty\.spawn\(\\"\/bin\/sh\\".{0,1000}\s\>\>\s\/etc\/update\-motd\.d\/00\-header/
                        $string32_DynastyPersist_offensive_tool_keyword = /spaceshuttle\.io\.all\@gmail\.com/
                        $string33_DynastyPersist_offensive_tool_keyword = "Trevohack/DynastyPersist"

    condition:
        any of them
}