rule APT_HackTool_MSIL_FLUFFY_2
{
    meta:
        date = "2020-12-04"
        modified = "2020-12-04"
        md5 = "11b5aceb428c3e8c61ed24a8ca50553e"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "ce39710e-7649-5f7d-bbbe-65dc30f678e8"
    strings:
        $s1 = "\x00Asktgt\x00"
        $s2 = "\x00Kerberoast\x00"
        $s3 = "\x00HarvestCommand\x00"
        $s4 = "\x00EnumerateTickets\x00"
        $s5 = "[*] Action: " wide
        $s6 = "\x00Fluffy.Commands\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}