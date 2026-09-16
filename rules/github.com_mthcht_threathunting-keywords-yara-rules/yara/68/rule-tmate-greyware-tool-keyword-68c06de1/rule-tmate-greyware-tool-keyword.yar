rule rule_tmate_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tmate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tmate"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tmate_greyware_tool_keyword = " install tmate"
                        $string2_tmate_greyware_tool_keyword = /\/\.tmate\.conf/
                        $string3_tmate_greyware_tool_keyword = "/tmate -k "
                        $string4_tmate_greyware_tool_keyword = /\/tmate\-ssh\-server\./
                        $string5_tmate_greyware_tool_keyword = /\/tmate\-ssh\-server\.git/
                        $string6_tmate_greyware_tool_keyword = "/tmate-ssh-server/releases/"
                        $string7_tmate_greyware_tool_keyword = "/tmp/tmate"
                        $string8_tmate_greyware_tool_keyword = "0965055fd620c556b5e515b292178d9fc77d04b5739c593be7c08e8b32ea93ec"
                        $string9_tmate_greyware_tool_keyword = "16eb3559cff7a2c2f02aef28b81c8677dc1d2c87dbbf81d5dadbec5c84eb3f3c"
                        $string10_tmate_greyware_tool_keyword = "1a092bc669e1aa4ffc86ef47e50b48aaa7fb330d39169225dc22e1ac98af691a"
                        $string11_tmate_greyware_tool_keyword = "39598a1e7623f06f98429b4d31706dd12e7cb8f2b62ef82a89796f529317a956"
                        $string12_tmate_greyware_tool_keyword = "43999af8d360359e36555f3a7843d4e987df5fc727e4fbd67e9bb1c4eff08150"
                        $string13_tmate_greyware_tool_keyword = "4ff03132d760141bc5f6e4ad0469be9081f179cf65e8f632c5c2c1eea1ed57ce"
                        $string14_tmate_greyware_tool_keyword = "52f5d95236e0d5eb73651af96e99d1da201164bfb63cea329aa25e01e2609463"
                        $string15_tmate_greyware_tool_keyword = "56c158d1060d6306a404027a06868c0c9475fec5d218d3e3746b1bddfe76c115"
                        $string16_tmate_greyware_tool_keyword = "632e9fb9eca80662e59afecf7eac6fb83026efdfe3f6e7d8ffbb06ca49dce4a7"
                        $string17_tmate_greyware_tool_keyword = "640ab98dba4d07fc0cfd6ecbab07244bbefb0d69575ce43a14ebb4f589de016b"
                        $string18_tmate_greyware_tool_keyword = "6e503a1a3b0f9117bce6ff7cc30cf61bdc79e9b32d074cf96deb0264e067a60d"
                        $string19_tmate_greyware_tool_keyword = "887db63eb3481f3a32aa449b84cbc44b4059ba2eacb869a87e965c10b4ce0173"
                        $string20_tmate_greyware_tool_keyword = "9bb687cca974dcb711e07739d9eaa8ed124519c2531a4442a0c0d320a75d8584"
                        $string21_tmate_greyware_tool_keyword = "9cfa910939a8af2fbf84786f386cb38d801981d9eb85337ac9694411e8133114"
                        $string22_tmate_greyware_tool_keyword = "bd6c9258ee73cd63d1b1a2aa02fda7cbefd1cee3ff17a590fc74613723625043"
                        $string23_tmate_greyware_tool_keyword = "c0339ea0fe2da7faf3e26186c09b27ba7697728311a98d5890ad504804395b8b"
                        $string24_tmate_greyware_tool_keyword = "cab846a2c20b581cb99f032f0e06c48baea38186f328c07d0f730e64b40f63b1"
                        $string25_tmate_greyware_tool_keyword = "d6777b4c6f1d93d8b23df1499c0ca56a9531ff823b07b923e094c9e9dba0d304"
                        $string26_tmate_greyware_tool_keyword = "dea4f15255d1b7f31845c80e1a49ace858044561465d60e5d8bbc029a404b150"
                        $string27_tmate_greyware_tool_keyword = "dfb7cd69256fb8b7d188f6819643ec10475b489c7d82c1950480e7b96f20116a"
                        $string28_tmate_greyware_tool_keyword = "ec7ce933860267a9fd6fb69a88ca01a8e5ec911910745fe8c2b6220cc0ab682f"
                        $string29_tmate_greyware_tool_keyword = "emerge -a app-misc/tmate"
                        $string30_tmate_greyware_tool_keyword = "f42dc28b48ba4a85f8127ccf118136aae48407eeee8c22a640d2d3ae755184d9"
                        $string31_tmate_greyware_tool_keyword = "fee0ecda586f1dfec39d0de21239642953ce228082a118e030fd76b4f827ae7c"
                        $string32_tmate_greyware_tool_keyword = "ffb2e75e9f58cb082f6cabb6e0a4794b0e22b037dc82abc3bc7ee8f376f44e23"
                        $string33_tmate_greyware_tool_keyword = /https\:\/\/tmate\.io\/t\//
                        $string34_tmate_greyware_tool_keyword = "pacman -S tmate"
                        $string35_tmate_greyware_tool_keyword = "pkg_add tmate"
                        $string36_tmate_greyware_tool_keyword = "set -g tmate-server-"
                        $string37_tmate_greyware_tool_keyword = "set tmate-api-key "
                        $string38_tmate_greyware_tool_keyword = "set tmate-authorized-keys"
                        $string39_tmate_greyware_tool_keyword = "set tmate-session-name "
                        $string40_tmate_greyware_tool_keyword = "set-option -g tmate-webhook-"
                        $string41_tmate_greyware_tool_keyword = /ssh\s.{0,1000}\.tmate\.io/
                        $string42_tmate_greyware_tool_keyword = /sudo\s\.\/tmate\-ssh\-server/
                        $string43_tmate_greyware_tool_keyword = /tmate\s\-a\s\~\/\.ssh\/authorized_keys/
                        $string44_tmate_greyware_tool_keyword = "tmate -F -n "
                        $string45_tmate_greyware_tool_keyword = "tmate -S /tmp"
                        $string46_tmate_greyware_tool_keyword = "tmate/tmate-ssh-server"
                        $string47_tmate_greyware_tool_keyword = "tmate-io/tmate"

    condition:
        any of them
}