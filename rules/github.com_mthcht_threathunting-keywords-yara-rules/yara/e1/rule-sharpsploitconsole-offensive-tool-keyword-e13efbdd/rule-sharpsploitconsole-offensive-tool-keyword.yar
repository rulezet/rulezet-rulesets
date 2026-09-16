rule rule_SharpSploitConsole_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSploitConsole' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSploitConsole"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSploitConsole_offensive_tool_keyword = /\/SharpSploit\.dll/ nocase ascii wide
                        $string2_SharpSploitConsole_offensive_tool_keyword = /\/SharpSploitConsole\.git/ nocase ascii wide
                        $string3_SharpSploitConsole_offensive_tool_keyword = /\\SharpSploit\.dll/ nocase ascii wide
                        $string4_SharpSploitConsole_offensive_tool_keyword = /\\SharpSploitConsole\./ nocase ascii wide
                        $string5_SharpSploitConsole_offensive_tool_keyword = "3787435B-8352-4BD8-A1C6-E5A1B73921F4" nocase ascii wide
                        $string6_SharpSploitConsole_offensive_tool_keyword = "6511e5a343746d582d9e5f598ac329eb56ccde68429c880b1a9e551f5c27083d" nocase ascii wide
                        $string7_SharpSploitConsole_offensive_tool_keyword = "anthemtotheego/SharpSploitConsole" nocase ascii wide
                        $string8_SharpSploitConsole_offensive_tool_keyword = "c12b1320138b4fd7578d7b1b4741bba50f115c8dcf7c3eb3d30bf939de134ade" nocase ascii wide
                        $string9_SharpSploitConsole_offensive_tool_keyword = "Executes a chosen Mimikatz command" nocase ascii wide
                        $string10_SharpSploitConsole_offensive_tool_keyword = "Executes everything but DCSync - requires admin" nocase ascii wide
                        $string11_SharpSploitConsole_offensive_tool_keyword = "Kerberoast -username " nocase ascii wide
                        $string12_SharpSploitConsole_offensive_tool_keyword = "Mimi-Command " nocase ascii wide
                        $string13_SharpSploitConsole_offensive_tool_keyword = "Mimi-Command privilege::" nocase ascii wide
                        $string14_SharpSploitConsole_offensive_tool_keyword = "Performs a kerberoasting attack against targeted" nocase ascii wide
                        $string15_SharpSploitConsole_offensive_tool_keyword = "Retrieve Domain Cached Credentials hashes from registry" nocase ascii wide
                        $string16_SharpSploitConsole_offensive_tool_keyword = "Retrieve LSA secrets stored in registry" nocase ascii wide
                        $string17_SharpSploitConsole_offensive_tool_keyword = "Retrieve Wdigest credentials from registry" nocase ascii wide
                        $string18_SharpSploitConsole_offensive_tool_keyword = "Runs a powershell command while attempting to bypass AMSI" nocase ascii wide
                        $string19_SharpSploitConsole_offensive_tool_keyword = "SharpSploit Command Execution" nocase ascii wide
                        $string20_SharpSploitConsole_offensive_tool_keyword = "SharpSploit Credentials Commands" nocase ascii wide
                        $string21_SharpSploitConsole_offensive_tool_keyword = "SharpSploit Domain Enumeration Commands" nocase ascii wide
                        $string22_SharpSploitConsole_offensive_tool_keyword = "SharpSploit Enumeration Commands" nocase ascii wide
                        $string23_SharpSploitConsole_offensive_tool_keyword = "SharpSploit Lateral Movement Commands" nocase ascii wide
                        $string24_SharpSploitConsole_offensive_tool_keyword = /SharpSploit\.Enumeration\./ nocase ascii wide
                        $string25_SharpSploitConsole_offensive_tool_keyword = /sharpSploitConsole\.exe/ nocase ascii wide
                        $string26_SharpSploitConsole_offensive_tool_keyword = /SharpSploitConsole\.sln/ nocase ascii wide
                        $string27_SharpSploitConsole_offensive_tool_keyword = "SharpSploitConsole:>" nocase ascii wide
                        $string28_SharpSploitConsole_offensive_tool_keyword = "SharpSploitConsole-master" nocase ascii wide

    condition:
        any of them
}