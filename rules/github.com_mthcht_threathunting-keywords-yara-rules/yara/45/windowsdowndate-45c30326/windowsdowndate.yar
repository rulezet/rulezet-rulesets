rule WindowsDowndate
{
    meta:
        description = "Detection patterns for the tool 'WindowsDowndate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WindowsDowndate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\swindows_downdate\.py/ nocase ascii wide
                        $string2 = /\/windows_downdate\.py/ nocase ascii wide
                        $string3 = /\/WindowsDowndate\.git/ nocase ascii wide
                        $string4 = /\\windows_downdate\.py/ nocase ascii wide
                        $string5 = /\\WindowsDowndate\-main/ nocase ascii wide
                        $string6 = "0a0be178cd014f569eac8697ce355c7ceb59b7e1a3aaa18673a7ffde4a044c88" nocase ascii wide
                        $string7 = "50eb54d0976374701c6051c23b993708,4d67d3d82b1adcc1b96e743e9b0efaaa8a566e3d,a34e71ededf334d3d6a480e3738c91fccbb4d2c1fbeec7192db9793a2541e8ca" nocase ascii wide
                        $string8 = /CVE\-2021\-27090\-Secure\-Kernel\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string9 = /CVE\-2022\-34709\-Credential\-Guard\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string10 = /CVE\-2023\-21768\-AFD\-Driver\-EoP\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string11 = "dab858feab4506727059fda4645865e2029892c6560704a7077433bab5d5ca0e" nocase ascii wide
                        $string12 = /from\swindows_downdate\./ nocase ascii wide
                        $string13 = /Hyper\-V\-Hypervisor\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string14 = /Kernel\-Suite\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string15 = /PPLFault\-Patch\-Downgrade\/Config\.xml/ nocase ascii wide
                        $string16 = "SafeBreach-Labs/WindowsDowndate" nocase ascii wide
                        $string17 = "Starting Windows-Downdate" nocase ascii wide
                        $string18 = /VBS\-UEFI\-Locks\-Bypass\/Config\.xml/ nocase ascii wide
                        $string19 = "Windows Downdate: Craft any downgrading Windows Updates" nocase ascii wide
                        $string20 = /windows_downdate\.exe/ nocase ascii wide
                        $string21 = "Windows-Downdate must be run as an Administrator" nocase ascii wide

    condition:
        any of them
}