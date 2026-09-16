rule _Trojan_Autorun_Gen_Trojan_Backdoor2_HmZbaKq9kbjb_8_Virus_Hijack_419 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Trojan.Backdoor2.HmZbaKq9kbjb_8.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_13_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_163_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_189_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_201_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_241_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_259_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_41.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9828657621996bbeea1519edbc2d237807230291dabde50e73596d757565f994"
    hash2       = "95cdc6e1c462932b44d96c9ee434cc3de4e20acab7717abaf524c17315d585b8"
    hash3       = "3ac7f62f4ef222c43700d5ec2ba2b4cd37515edba3ef6b7c1ee7459419d5c702"
    hash4       = "44fedf6976cda29deef5c664184651784a3b1c9a4c6b07f59acd093eebadee7d"
    hash5       = "d48ef14c519404cf9329c4b269ef6966219667ab04e71cdecb5929c364d58c84"
    hash6       = "b45e19ca33e2a0b101541844bf1852c429c2e5a6b6a40129c721ea9b75629c90"
    hash7       = "fd3bef3a8bd095762b6f798515a7c714f605fa8a1619a40f0b3016a31c5bf00c"
    hash8       = "aed769307e38ba23233c9e5bd676f009bcc5871cc4f6dd1447e662ca109bd72d"
    hash9       = "67ef84dfef19e55a6c230a10a42f614fe523d062ea7f152c7a31b30b4f4a31ff"
    hash10      = "d38ed19cfb2457a7b7ad16624740f7634a10d27be7b9f4d2bdcfa1cd81064139"
    hash11      = "bc0068b0dd00d800c6a777227a1aecddb53b886ed33ee9b6b5694b0edbcb4c31"

  strings:
    $s1  = "English=Setup needs to restart your system to complete the installation.  Do you want to restart now?" fullword wide
    $s2  = "Croatian=Program za postavljanje mora ponovo pokrenuti va" fullword wide
    $s3  = "Danish=Installationsprogrammet skal genstarte systemet for at afslutte installationen. Vil du genstarte nu?" fullword wide
    $s4  = "Dutch=De computer moet opnieuw worden opgestart om de installatie te voltooien. Wilt u de computer nu opnieuw opstarten?" fullword wide
    $s5  = "German=Setup  muss das System zum Beenden der Installation neu starten. Jetzt neu starten?" fullword wide
    $s6  = " system.  Czy chcesz uruchomi" fullword wide
    $s7  = "czenia instalacji program instalacyjny musi ponownie uruchomi" fullword wide
    $s8  = " program re" fullword wide
    $s9  = "elite li odmah ponovo pokrenuti sustav?" fullword wide
    $s10 = "tja most?" fullword wide
    $s11 = "tart teraz?" fullword wide
    $s12 = "Slovenian=Namestitveni program mora znova zagnati sistem, da bi dokon" fullword wide
    $s13 = "elite sistem znova zagnati zdaj?" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}