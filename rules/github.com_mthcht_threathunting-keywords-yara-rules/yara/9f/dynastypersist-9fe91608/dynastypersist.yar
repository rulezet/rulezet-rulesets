rule DynastyPersist
{
    meta:
        description = "Detection patterns for the tool 'DynastyPersist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DynastyPersist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdynasty\.sh/
                        $string2 = /\srce\.php\s\/var/
                        $string3 = /\.\/dynasty\.sh/
                        $string4 = /\/DynastyPersist\.git/
                        $string5 = /\/DynastyPersist\/src\/.{0,1000}\.sh/
                        $string6 = /\/var\/tmp\/\.memory\/diamorphine\.c/
                        $string7 = /\/var\/tmp\/\.memory\/diamorphine\.h/
                        $string8 = "/var/www/html/dynasty_rce"
                        $string9 = /\[\+\]\s\-\sBashrc\spersistence\sadded\!/
                        $string10 = /\[\+\]\s\-\sConfiguring\s\~\/\.bashrc\sfor\spersistence\s\.\.\.\s/
                        $string11 = /\[\+\]\s\-\sLinux\sheader\s\/\sMessage\sOf\sThe\sDay\sPersistence/
                        $string12 = /\[\+\]\s\-\sRootkit\sConfiguration/
                        $string13 = /\[\+\]\s\-\sRootkit\sconfigured\ssuccessfully/
                        $string14 = /\[\+\]\s\-\sSetting\sup\scronjobs\sfor\spersistence\s\.\.\.\s/
                        $string15 = /\[\+\]\s\-\sSystemd\sRoot\sLevel\sService\ssuccessfully\sconfigued\!/
                        $string16 = /\[\+\]\sSuccess\!\sLD_PRELOAD\shas\sbeen\sadded\!/
                        $string17 = /\\DynastyPersist\\src\\.{0,1000}\.sh/
                        $string18 = "<title>Dynasty Persist</title>"
                        $string19 = "D Y N A S T Y  - P E R S I S T"
                        $string20 = /dynasty_rce\/rce\.php/
                        $string21 = /DynastyPersist\-main\.zip/
                        $string22 = /echo\s\\"Nothing\sto\ssee\shere\s\.\.\.\s\\"\s\>\s\/var\/log\/kern\.log/
                        $string23 = /echo\s\'alias\scat\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'\'\s\>\>\s.{0,1000}\/\.bashrc.{0,1000}\s/
                        $string24 = /echo\s\'find\scat\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'\'\s\>\>\s.{0,1000}\/\.bashrc.{0,1000}\s/
                        $string25 = "ExecStartPre present! ExecStartPre was modified!"
                        $string26 = /https\:\/\/github\.com\/m0nad\/Diamorphine/
                        $string27 = "LDPreloadPrivesc"
                        $string28 = /Made\sby\:\s\@Trevohack\s\|\s\@opabravo\s\|\s\@matheuz/
                        $string29 = /Modified\sby\:\sTrevohack\saka\s.{0,1000}SpaceShuttleIO/
                        $string30 = /php\s\-S\s0\.0\.0\.0\:9056\s\&/
                        $string31 = /pty\.spawn\(\\"\/bin\/sh\\".{0,1000}\s\>\>\s\/etc\/update\-motd\.d\/00\-header/
                        $string32 = /spaceshuttle\.io\.all\@gmail\.com/
                        $string33 = "Trevohack/DynastyPersist"

    condition:
        any of them
}