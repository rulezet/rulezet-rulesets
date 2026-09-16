rule DirCreate2System
{
    meta:
        description = "Detection patterns for the tool 'DirCreate2System' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DirCreate2System"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DirCreate2System\.git/ nocase ascii wide
                        $string2 = /\/DirCreate2System\.git/ nocase ascii wide
                        $string3 = /\[\+\]\sArbitrary\sDirectory\sCreation\sto\sSYSTEM\sShell\stechnique\s\!/ nocase ascii wide
                        $string4 = /\[\+\]\sFinding\sdirectory\sto\shijack/ nocase ascii wide
                        $string5 = /\[\+\]\sPoc\sBy\s\@404death\s/ nocase ascii wide
                        $string6 = /\[\+\]\sSpawning\sSYSTEM\sshell/ nocase ascii wide
                        $string7 = /\\dircreate2system\.pdb/ nocase ascii wide
                        $string8 = /\\dircreate2system\.sln/ nocase ascii wide
                        $string9 = /\\DirCreate2System\\bin\\/ nocase ascii wide
                        $string10 = "36c88f1852f3c162bf64d973bb6f69ffb7e22503015e104716fc51eaddcbe875" nocase ascii wide
                        $string11 = "765C5755-DBE9-4AB5-9427-921D0E46F9F0" nocase ascii wide
                        $string12 = "7EE536AE-6C1D-4881-88F7-37C8F2A0CA50" nocase ascii wide
                        $string13 = "binderlabs/DirCreate2System" nocase ascii wide
                        $string14 = "binderlabs/DirCreate2System" nocase ascii wide
                        $string15 = /cacls\sC\:\\Windows\\System32\\wermgr\.exe\.local\s\/e\s\/g\severyone\:f/ nocase ascii wide
                        $string16 = /dir_create2system\.txt/ nocase ascii wide
                        $string17 = /dircreate2system\.cpp/ nocase ascii wide
                        $string18 = /dircreate2system\.exe/ nocase ascii wide
                        $string19 = /dircreate2system\.vcxproj/ nocase ascii wide
                        $string20 = "DirCreate2System-main" nocase ascii wide
                        $string21 = /dll_spawn_cmd\.cpp/ nocase ascii wide
                        $string22 = /dll_spawn_cmd\.exe/ nocase ascii wide
                        $string23 = "ebfebca063aa056d7ffd8767c7c82d66c0c1a4339eb504a8e0636280dc5b839f" nocase ascii wide

    condition:
        any of them
}