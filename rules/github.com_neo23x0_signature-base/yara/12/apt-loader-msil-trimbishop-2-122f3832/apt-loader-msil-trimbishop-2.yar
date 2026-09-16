rule APT_Loader_MSIL_TRIMBISHOP_2
{
    meta:
        date = "2020-12-03"
        modified = "2020-12-03"
        md5 = "c0598321d4ad4cf1219cc4f84bad4094"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "90ee2569-2e68-517b-b2d7-8c4015d92683"
    strings:
        $ss1 = "\x00NtMapViewOfSection\x00"
        $ss2 = "\x00NtOpenProcess\x00"
        $ss3 = "\x00NtAlertResumeThread\x00"
        $ss4 = "\x00LdrGetProcedureAddress\x00"
        $ss5 = "\x2f(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00i\x00|\x00I\x00n\x00j\x00e\x00c\x00t\x00)\x00$\x00"
        $ss6 = "\x2d(\x00?\x00i\x00)\x00(\x00-\x00|\x00-\x00-\x00|\x00/\x00)\x00(\x00c\x00|\x00C\x00l\x00e\x00a\x00n\x00)\x00$\x00"
        $tb1 = "\x00DTrim.Execution.DynamicInvoke\x00"
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}