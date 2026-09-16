rule APT_Loader_Win64_PGF_4
{
    meta:
        date = "2020-11-26"
        modified = "2020-11-26"
        md5 = "3bb34ebd93b8ab5799f4843e8cc829fa"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "4c93ba76-d3a5-568d-88b8-79a6ebc2edbb"
    strings:
        $sb1 = { 41 B9 04 00 00 00 41 B8 00 10 00 00 BA [4] B9 00 00 00 00 [0-32] FF [1-24] 7? [1-150] 8B 45 [0-32] 44 0F B? ?? 8B [2-16] B? CD CC CC CC [0-16] C1 ?? 04 [0-16] C1 ?? 02 [0-16] C1 ?? 02 [0-16] 48 8? 05 [4-32] 31 [1-4] 88 }
        $sb2 = { C? 45 ?? 48 [0-32] B8 [0-64] FF [0-32] E0 [0-32] 41 B8 40 00 00 00 BA 0C 00 00 00 48 8B [2] 48 8B [2-32] FF [1-16] 48 89 10 8B 55 ?? 89 ?? 08 48 8B [2] 48 8D ?? 02 48 8B 45 18 48 89 02 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B) and all of them
}