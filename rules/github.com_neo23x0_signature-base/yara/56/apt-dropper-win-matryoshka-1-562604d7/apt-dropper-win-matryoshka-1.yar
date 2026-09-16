rule APT_Dropper_Win_MATRYOSHKA_1
{
    meta:
        date = "2020-12-02"
        modified = "2020-12-02"
        description = "matryoshka_dropper.rs"
        md5 = "edcd58ba5b1b87705e95089002312281"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "7fd305c7-0b1b-5d91-b968-7f1fb0a8ae47"
    strings:
        $s1 = "\x00matryoshka.exe\x00"
        $s2 = "\x00Unable to write data\x00"
        $s3 = "\x00Error while spawning process. NTStatus: \x0a\x00"
        $s4 = "\x00.execmdstart/Cfailed to execute process\x00"
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}