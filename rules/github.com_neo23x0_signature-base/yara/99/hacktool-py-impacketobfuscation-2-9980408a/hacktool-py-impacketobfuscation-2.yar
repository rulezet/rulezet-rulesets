rule HackTool_PY_ImpacketObfuscation_2
{
    meta:
        description = "Detects FireEye's wmiexec impacket obfuscation"
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "f3dd8aa567a01098a8a610529d892485"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "f1059f66-eaff-5866-bafb-c94236cf96a0"
    strings:
        $s1 = "import random"
        $s2 = "class WMIEXEC" nocase
        $s3 = "class RemoteShell" nocase
        $s4 = /=[\x09\x20]{0,32}str\(int\(time\.time\(\)\)[\x09\x20]{0,32}-[\x09\x20]{0,32}random\.randint\(\d{1,10}[\x09\x20]{0,32},[\x09\x20]{0,32}\d{1,10}\)\)[\x09\x20]{0,32}\+[\x09\x20]{0,32}str\(uuid\.uuid4\(\)\)\.split\([\x22\x27]\-[\x22\x27]\)\[0\]/
        $s5 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]cmd.exe[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
    condition:
        all of them
}