rule SharpSploitConsole
{
    meta:
        description = "Detection patterns for the tool 'SharpSploitConsole' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSploitConsole"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpSploit\.dll/ nocase ascii wide
                        $string2 = /\/SharpSploitConsole\.git/ nocase ascii wide
                        $string3 = /\\SharpSploit\.dll/ nocase ascii wide
                        $string4 = /\\SharpSploitConsole\./ nocase ascii wide
                        $string5 = "3787435B-8352-4BD8-A1C6-E5A1B73921F4" nocase ascii wide
                        $string6 = "6511e5a343746d582d9e5f598ac329eb56ccde68429c880b1a9e551f5c27083d" nocase ascii wide
                        $string7 = "anthemtotheego/SharpSploitConsole" nocase ascii wide
                        $string8 = "c12b1320138b4fd7578d7b1b4741bba50f115c8dcf7c3eb3d30bf939de134ade" nocase ascii wide
                        $string9 = "Executes a chosen Mimikatz command" nocase ascii wide
                        $string10 = "Executes everything but DCSync - requires admin" nocase ascii wide
                        $string11 = "Kerberoast -username " nocase ascii wide
                        $string12 = "Mimi-Command " nocase ascii wide
                        $string13 = "Mimi-Command privilege::" nocase ascii wide
                        $string14 = "Performs a kerberoasting attack against targeted" nocase ascii wide
                        $string15 = "Retrieve Domain Cached Credentials hashes from registry" nocase ascii wide
                        $string16 = "Retrieve LSA secrets stored in registry" nocase ascii wide
                        $string17 = "Retrieve Wdigest credentials from registry" nocase ascii wide
                        $string18 = "Runs a powershell command while attempting to bypass AMSI" nocase ascii wide
                        $string19 = "SharpSploit Command Execution" nocase ascii wide
                        $string20 = "SharpSploit Credentials Commands" nocase ascii wide
                        $string21 = "SharpSploit Domain Enumeration Commands" nocase ascii wide
                        $string22 = "SharpSploit Enumeration Commands" nocase ascii wide
                        $string23 = "SharpSploit Lateral Movement Commands" nocase ascii wide
                        $string24 = /SharpSploit\.Enumeration\./ nocase ascii wide
                        $string25 = /sharpSploitConsole\.exe/ nocase ascii wide
                        $string26 = /SharpSploitConsole\.sln/ nocase ascii wide
                        $string27 = "SharpSploitConsole:>" nocase ascii wide
                        $string28 = "SharpSploitConsole-master" nocase ascii wide

    condition:
        any of them
}