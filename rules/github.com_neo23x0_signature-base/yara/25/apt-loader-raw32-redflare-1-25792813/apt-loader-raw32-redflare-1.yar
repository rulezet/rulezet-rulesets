rule APT_Loader_Raw32_REDFLARE_1
{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "4022baddfda3858a57c9cbb0d49f6f86"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "8f8ec27f-afac-5da5-b76f-b984e14e0066"
    strings:
        $load = { EB ?? 58 [0-4] 8B 10 8B 48 [1-3] 8B C8 83 C1 ?? 03 D1 83 E9 [1-3] 83 C1 [1-4] FF D? }
    condition:
        (uint16(0) != 0x5A4D) and all of them
}