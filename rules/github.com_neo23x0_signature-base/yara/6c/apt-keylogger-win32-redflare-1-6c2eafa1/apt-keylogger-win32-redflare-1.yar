rule APT_Keylogger_Win32_REDFLARE_1
{
    meta:
        description = "Detects REDFLARE Keylogger"
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "d7cfb9fbcf19ce881180f757aeec77dd"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "ad14db66-d640-5712-b2c8-a3d42d5a90f3"
    strings:
        $create_window = { 6A 00 68 [4] 6A 00 6A 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 CF 00 68 [4] 68 [4] 6A 00 FF 15 }
        $keys_check = { 6A 14 [0-5] FF [1-5] 6A 10 [0-5] FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A0 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 75 ?? 68 A1 00 00 00 FF [1-5] B9 00 80 FF FF 66 85 C1 74 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}