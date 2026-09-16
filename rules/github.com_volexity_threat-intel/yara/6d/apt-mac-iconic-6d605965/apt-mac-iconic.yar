rule apt_mac_iconic: UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-03-30"
        description = "Detects the MACOS version of the ICONIC loader."
        hash1 = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
        reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $str1 = "3CX Desktop App" xor(0x01-0xff)
        $str2 = "__tutma=" xor(0x01-0xff)
        $str3 = "Mozilla/5.0" xor(0x01-0xff)

    condition:
        all of them
}