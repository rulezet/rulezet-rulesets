rule rclone
{
    meta:
        description = "Detection patterns for the tool 'rclone' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rclone"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /Behavior\:Linux\/SuspRcloneSpawn\.A/ nocase ascii wide
                        $string2 = /Behavior\:Linux\/SuspRcloneSpawn\.B/ nocase ascii wide
                        $string3 = "Behavior:Win32/OFNRclone" nocase ascii wide
                        $string4 = /Behavior\:Win32\/PShellRclone\.SA/ nocase ascii wide
                        $string5 = /Behavior\:Win32\/RcloneConf\.A/ nocase ascii wide
                        $string6 = /Behavior\:Win32\/RcloneExfil\.S/ nocase ascii wide
                        $string7 = /Behavior\:Win32\/RcloneExfil\.SA/ nocase ascii wide
                        $string8 = /Behavior\:Win32\/RcloneMega\.SA\!Ofn/ nocase ascii wide
                        $string9 = /Behavior\:Win32\/RcloneMega\.SA/ nocase ascii wide
                        $string10 = /Behavior\:Win32\/RcloneSusExec\.A/ nocase ascii wide
                        $string11 = /Behavior\:Win32\/RcloneSusTLD\.A/ nocase ascii wide
                        $string12 = /Behavior\:Win32\/RcloneUAgent\.A/ nocase ascii wide
                        $string13 = /Behavior\:Win32\/RenamedToolRclone\.SA/ nocase ascii wide
                        $string14 = /Behavior\:Win32\/SuspRclone\.A/ nocase ascii wide
                        $string15 = /Behavior\:Win32\/SuspRclone\.B/ nocase ascii wide
                        $string16 = /Behavior\:Win32\/SuspRclone\.C/ nocase ascii wide
                        $string17 = /Behavior\:Win32\/SuspRclone\.D/ nocase ascii wide
                        $string18 = "HackTool:Win64/FakeRclone" nocase ascii wide

    condition:
        any of them
}