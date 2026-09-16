rule ADPassHunt
{
    meta:
        description = "Detection patterns for the tool 'ADPassHunt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADPassHunt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sADPassHunt\.GetGPPPassword/ nocase ascii wide
                        $string2 = /\[ADA\]\sSearching\sfor\saccounts\swith\smsSFU30Password\sattribute/ nocase ascii wide
                        $string3 = /\[ADA\]\sSearching\sfor\saccounts\swith\suserpassword\sattribute/ nocase ascii wide
                        $string4 = /\[GPP\]\sSearching\sfor\spasswords\snow/ nocase ascii wide
                        $string5 = /\\ADPassHunt\.pdb/ nocase ascii wide
                        $string6 = /\\ADPassHunt\\/ nocase ascii wide
                        $string7 = ">ADPassHunt<" nocase ascii wide
                        $string8 = "73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f" nocase ascii wide
                        $string9 = /AdPassHunt\s\(PUA\)/ nocase ascii wide
                        $string10 = /ADPassHunt\.exe/ nocase ascii wide
                        $string11 = "Get-GPPAutologons" nocase ascii wide
                        $string12 = "Get-GPPPasswords" nocase ascii wide
                        $string13 = "HackTool:Win32/PWDump" nocase ascii wide
                        $string14 = "HackTool:Win32/PWDump" nocase ascii wide
                        $string15 = /Win\.Tool\.ADPassHunt\-/ nocase ascii wide

    condition:
        any of them
}