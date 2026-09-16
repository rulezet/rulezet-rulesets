rule APT_Backdoor_Win_GORAT_1
{
    meta:
        description = "This detects if a sample is less than 50KB and has a number of strings found in the Gorat shellcode (stage0 loader). The loader contains an embedded DLL (stage0.dll) that contains a number of unique strings. The 'Cookie' string found in this loader is important as this cookie is needed by the C2 server to download the Gorat implant (stage1 payload)."
        md5 = "66cdaa156e4d372cfa3dea0137850d20"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "5ac84cf1-49fb-533d-b211-b1a92239063b"
    strings:
        $s1 = "httpComms.dll" ascii wide
        $s2 = "Cookie: SID1=%s" ascii wide
        $s3 = "Global\\" ascii wide
        $s4 = "stage0.dll" ascii wide
        $s5 = "runCommand" ascii wide
        $s6 = "getData" ascii wide
        $s7 = "initialize" ascii wide
        $s8 = "Windows NT %d.%d;" ascii wide
        $s9 = "!This program cannot be run in DOS mode." ascii wide
    condition:
        filesize < 50KB and all of them
}