rule rule_Sandman_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Sandman' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sandman"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Sandman_offensive_tool_keyword = /\ssandman_server\.py/ nocase ascii wide
                        $string2_Sandman_offensive_tool_keyword = "# If got a malicious packet - Activate the backdoor!" nocase ascii wide
                        $string3_Sandman_offensive_tool_keyword = /\/Sandman\.exe/ nocase ascii wide
                        $string4_Sandman_offensive_tool_keyword = /\/sandman_server\.py/ nocase ascii wide
                        $string5_Sandman_offensive_tool_keyword = /\/SandmanBackdoorTimeProvider\.dll/ nocase ascii wide
                        $string6_Sandman_offensive_tool_keyword = /\/Sandman\-master\.zip/ nocase ascii wide
                        $string7_Sandman_offensive_tool_keyword = /\[\s\+\s\]\sGot\sa\spacket\sfrom\sthe\sbackdoor\!/ nocase ascii wide
                        $string8_Sandman_offensive_tool_keyword = /\\Sandman\.exe/ nocase ascii wide
                        $string9_Sandman_offensive_tool_keyword = /\\sandman_server\.py/ nocase ascii wide
                        $string10_Sandman_offensive_tool_keyword = /\\SandmanBackdoorTimeProvider\.dll/ nocase ascii wide
                        $string11_Sandman_offensive_tool_keyword = /\\Sandman\-master\.zip/ nocase ascii wide
                        $string12_Sandman_offensive_tool_keyword = ">SandmanBackdoorTimeProvider<" nocase ascii wide
                        $string13_Sandman_offensive_tool_keyword = "037efb13ec86af0dd0aa92bae0e8dbb3d50de958e8936dfeb2938ee3ea4a3136" nocase ascii wide
                        $string14_Sandman_offensive_tool_keyword = "037efb13ec86af0dd0aa92bae0e8dbb3d50de958e8936dfeb2938ee3ea4a3136" nocase ascii wide
                        $string15_Sandman_offensive_tool_keyword = "1bc73a13029b5677f070a991cec0ed90f3ebd70bcc0566a4724496eb71792dee" nocase ascii wide
                        $string16_Sandman_offensive_tool_keyword = "74f0a367e0af7a5885ece4682a8e1a07945893090ecf8c9677310954c7d9c479" nocase ascii wide
                        $string17_Sandman_offensive_tool_keyword = "B362EC25-70BD-4E6C-9744-173D20FDA392" nocase ascii wide
                        $string18_Sandman_offensive_tool_keyword = "E9F7C24C-879D-49F2-B9BF-2477DC28E2EE" nocase ascii wide
                        $string19_Sandman_offensive_tool_keyword = "f34befa3856ca7fedc2081903e35dff0eb86147aa6e163169355e46f8d5c3c98" nocase ascii wide
                        $string20_Sandman_offensive_tool_keyword = "Idov31/Sandman" nocase ascii wide
                        $string21_Sandman_offensive_tool_keyword = "MALICIOUS_MAGIC = b\"IDOV31\"" nocase ascii wide
                        $string22_Sandman_offensive_tool_keyword = /reg\sadd\s\\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient\\\\"\s\/v\s.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}