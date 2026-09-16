rule HackTool_PY_ImpacketObfuscation_1
{
    meta:
        date = "2020-12-01"
        modified = "2020-12-01"
        description = "smbexec"
        md5 = "0b1e512afe24c31531d6db6b47bac8ee"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
        id = "992d1132-3136-5e1b-a1ef-dcdf36ebf0f5"
    strings:
        $s1 = "class CMDEXEC" nocase
        $s2 = "class RemoteShell" nocase
        $s3 = "self.services_names"
        $s4 = "import random"
        $s6 = /self\.__shell[\x09\x20]{0,32}=[\x09\x20]{0,32}[\x22\x27]%CoMSpEC%[\x09\x20]{1,32}\/q[\x09\x20]{1,32}\/K [\x22\x27]/ nocase
        $s7 = /self\.__serviceName[\x09\x20]{0,32}=[\x09\x20]{0,32}self\.services_names\[random\.randint\([\x09\x20]{0,32}0[\x09\x20]{0,32},[\x09\x20]{0,32}len\(self\.services_names\)[\x09\x20]{0,32}-[\x09\x20]{0,32}1\)\]/
    condition:
        all of them
}