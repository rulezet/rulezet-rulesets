rule HackTool_MSIL_SharPivot_2
{
    meta:
        description = "Detects FireEye's SharPivot tool"
        md5 = "e4efa759d425e2f26fbc29943a30f5bd"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "8d6d28ce-de3a-5a38-b654-ba1372d47568"
    strings:
        $s1 = "costura"
        $s2 = "cmd_schtask" wide
        $s3 = "cmd_wmi" wide
        $s4 = "cmd_rpc" wide
        $s5 = "GoogleUpdateTaskMachineUA" wide
        $s6 = "servicehijack" wide
        $s7 = "poisonhandler" wide
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}