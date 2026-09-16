rule APT_Loader_Raw64_REDFLARE_1
{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "5e14f77f85fd9a5be46e7f04b8a144f5"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "8e937f6a-404f-53bd-9de2-ed63b1cf48b2"
    strings:
        $load = { EB ?? 58 48 8B 10 4C 8B 48 ?? 48 8B C8 [1-10] 48 83 C1 ?? 48 03 D1 FF }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}