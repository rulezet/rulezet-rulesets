rule _Virus_Hijack_Dropped_Backdoor_Padodor_BJ_683_1_Virus_Hijack_Tro_555 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Backdoor.Padodor.BJ_683_1.vir, Virus.Hijack_Trojan.Agent.DQQO_162_2.vir, Virus.Hijack_Trojan.Agent.DQQO_163_2.vir, Virus.Sysbot_Trojan.GenericKDZ.105157.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "520f541ef6c86ca0d365d3ed63a2f7eadb6ad690de4b0dbacf69ea4d4984648e"
    hash2       = "cdebfb2008f0cdd769d922a926c0bd74ec2eb682ed935aeb18551018e40d7f5f"
    hash3       = "7cab2b38473191d9c8a6d48a0dd0d0e229453872e6c0c1fbb6287f30cd565894"
    hash4       = "6d34c78b180f8e96fe8d40cd2a3df7f3bdca39d84f7999d1a5fedf4f0213bd67"

  strings:
    $s1 = "Unable to modify directories in target executable.  File may not contain any icon resources." fullword wide
    $s2 = " is not a valid Win32 executable." fullword wide
    $s3 = " does not contain a valid resource tree.  File may be corrupt." fullword wide
    $s4 = ". Make sure file is not in use by another program." fullword wide
    $s5 = " is not a valid icon resource file." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}