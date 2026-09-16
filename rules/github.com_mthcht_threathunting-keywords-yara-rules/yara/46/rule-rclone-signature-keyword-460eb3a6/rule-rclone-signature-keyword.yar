rule rule_rclone_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'rclone' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rclone"
        rule_category = "signature_keyword"

    strings:
                        $string1_rclone_signature_keyword = /Behavior\:Linux\/SuspRcloneSpawn\.A/ nocase ascii wide
                        $string2_rclone_signature_keyword = /Behavior\:Linux\/SuspRcloneSpawn\.B/ nocase ascii wide
                        $string3_rclone_signature_keyword = "Behavior:Win32/OFNRclone" nocase ascii wide
                        $string4_rclone_signature_keyword = /Behavior\:Win32\/PShellRclone\.SA/ nocase ascii wide
                        $string5_rclone_signature_keyword = /Behavior\:Win32\/RcloneConf\.A/ nocase ascii wide
                        $string6_rclone_signature_keyword = /Behavior\:Win32\/RcloneExfil\.S/ nocase ascii wide
                        $string7_rclone_signature_keyword = /Behavior\:Win32\/RcloneExfil\.SA/ nocase ascii wide
                        $string8_rclone_signature_keyword = /Behavior\:Win32\/RcloneMega\.SA\!Ofn/ nocase ascii wide
                        $string9_rclone_signature_keyword = /Behavior\:Win32\/RcloneMega\.SA/ nocase ascii wide
                        $string10_rclone_signature_keyword = /Behavior\:Win32\/RcloneSusExec\.A/ nocase ascii wide
                        $string11_rclone_signature_keyword = /Behavior\:Win32\/RcloneSusTLD\.A/ nocase ascii wide
                        $string12_rclone_signature_keyword = /Behavior\:Win32\/RcloneUAgent\.A/ nocase ascii wide
                        $string13_rclone_signature_keyword = /Behavior\:Win32\/RenamedToolRclone\.SA/ nocase ascii wide
                        $string14_rclone_signature_keyword = /Behavior\:Win32\/SuspRclone\.A/ nocase ascii wide
                        $string15_rclone_signature_keyword = /Behavior\:Win32\/SuspRclone\.B/ nocase ascii wide
                        $string16_rclone_signature_keyword = /Behavior\:Win32\/SuspRclone\.C/ nocase ascii wide
                        $string17_rclone_signature_keyword = /Behavior\:Win32\/SuspRclone\.D/ nocase ascii wide
                        $string18_rclone_signature_keyword = "HackTool:Win64/FakeRclone" nocase ascii wide

    condition:
        any of them
}