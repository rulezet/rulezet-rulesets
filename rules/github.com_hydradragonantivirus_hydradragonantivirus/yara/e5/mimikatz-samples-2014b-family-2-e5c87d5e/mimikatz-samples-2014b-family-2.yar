rule Mimikatz_Samples_2014b_Family_2 {
  meta:
    description = "Mimikatz pwassword dumper samples from the second half of 2014"
    author      = "Florian Roth with the help of YarGen Rule Generator"
    date        = "2014/12/23"
    super_rule  = 1
    score       = 80
    hash0       = "61001a32c5388e629dd0441a77974200057816ef"
    hash1       = "46df272cecb541aebca3c863802c0d0a0dc5fcb4"
    hash2       = "c3307bb70efa19fc5049dfd829d07ea52a65bb74"
    hash3       = "29d9bfc4e4884bc7b2f3cd01960b727c17fb50cb"
    hash4       = "ac1d1db32ca6e7af5625f0f6fbe210fe68002b5c"

  strings:
    $s0  = "ncryptprov.dll" fullword wide
    $s1  = "CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY" fullword wide
    $s2  = "logonPasswords" fullword wide
    $s3  = "CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE" fullword wide
    $s4  = "CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY" fullword wide
    $s5  = "inject" fullword wide
    $s6  = "MS_DEF_RSA_SCHANNEL_PROV" fullword wide
    $s7  = "MS_ENHANCED_PROV" fullword wide
    $s8  = "MS_DEF_RSA_SIG_PROV" fullword wide
    $s9  = "privilege" fullword wide
    $s10 = "MS_ENH_RSA_AES_PROV" fullword wide
    $s16 = "sekurlsa" fullword wide
    $s17 = "answer" fullword wide
    $s18 = "secrets" fullword wide
    $s19 = "MS_DEF_DSS_PROV" fullword wide
    $s20 = "MS_DEF_PROV" fullword wide

  condition:
    all of them
}