rule BrowserSnatch
{
    meta:
        description = "Detection patterns for the tool 'BrowserSnatch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BrowserSnatch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/BrowserSnatch\.git/ nocase ascii wide
                        $string2 = "/BrowserSnatch/releases/download" nocase ascii wide
                        $string3 = "/BrowserSnatch-master" nocase ascii wide
                        $string4 = /\\BrowserSnatch\.sln/ nocase ascii wide
                        $string5 = /\\BrowserSnatch\-master/ nocase ascii wide
                        $string6 = /\\ChromiumDecryptor\.cpp/ nocase ascii wide
                        $string7 = "08cebde6781422f271581951ff6db23b9eedd4a0be0949551c0da85c6de8cb72" nocase ascii wide
                        $string8 = "0f898913633b4dad45a631e63466f6b76e591f896118bab6e718ab3c8587911f" nocase ascii wide
                        $string9 = "3246bb6e6b258b85286ae566dbde16e6e61c35d21be06a0d03b1aad376efb411" nocase ascii wide
                        $string10 = "3f8db721f5791fcaaef7d22b50a1cd6a87be8f07262c145ad66a18f832d75839" nocase ascii wide
                        $string11 = "493e415ef774fe3a7c3ba17a524f02d72bd36b1a49d8e9e0734eecf1d5834155" nocase ascii wide
                        $string12 = "569d0ac16a89509e1de01deab2fefe2731a48bec2ab7794d9ac0628a6baf2481" nocase ascii wide
                        $string13 = "7dbc46ea673ab508a7b9121b0a49d29470a8fc01669105173fd2a52f88dd946a" nocase ascii wide
                        $string14 = "7de6e20c24d452409937f4869770848445952afa1ff26288dfb558d8edc64def" nocase ascii wide
                        $string15 = "87440f0b-dacf-4695-a483-031fdc0b0194" nocase ascii wide
                        $string16 = "a3fbc9a01ac82d10f92da72625f1a092817c5fad7a9b60917b811fab1ff8c97f" nocase ascii wide
                        $string17 = "BrowserSnatch -" nocase ascii wide
                        $string18 = "BrowserSnatch executed with " nocase ascii wide
                        $string19 = /BrowserSnatch\sv1\.0\s\-\sA\sversatile\sbrowser\sdata\sextraction\stool/ nocase ascii wide
                        $string20 = /BrowserSnatch\.exe/ nocase ascii wide
                        $string21 = /BrowserSnatch64\.exe/ nocase ascii wide
                        $string22 = /BrowserSnatch\-master\.zip/ nocase ascii wide
                        $string23 = "Chromium Bookmarks Snatch Failed" nocase ascii wide
                        $string24 = "Chromium Cookie Snatch Failed" nocase ascii wide
                        $string25 = "Chromium History Snatch Failed" nocase ascii wide
                        $string26 = "Chromium Password Snatch Failed" nocase ascii wide
                        $string27 = "dc12cf2c161aea6ad015a11593b74603e25a4c7754b96b3d3b4062bd0e5d5a09" nocase ascii wide
                        $string28 = /dns\.msfncsi\.com/ nocase ascii wide
                        $string29 = "e7711f13b26f4b8f260587592d92f5d04e4aec5124896a35f082b69785e51d26" nocase ascii wide
                        $string30 = "f58cbacfd41c4b0d5411a48f8142489dbde75c79211f37cb3c11a5063ebb6c2f" nocase ascii wide
                        $string31 = "Gecko Bookmarks Snatch Failed" nocase ascii wide
                        $string32 = "Gecko Cookie Snatch Failed" nocase ascii wide
                        $string33 = "Gecko History Snatch Failed" nocase ascii wide
                        $string34 = "Gecko Password Snatch Failed" nocase ascii wide
                        $string35 = /https\:\/\/0x00sec\.org\/t\/malware\-development\-1\-password\-stealers\-chrome\/33571/ nocase ascii wide
                        $string36 = "shaddy43/BrowserSnatch" nocase ascii wide
                        $string37 = "Snatching passwords & cookies" nocase ascii wide

    condition:
        any of them
}