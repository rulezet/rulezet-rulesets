rule _Virus_Autorun_Gen_Heur_Mint_Autorunner_1_Virus_Autorun_Gen_Vari_481 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Heur.Mint.Autorunner.1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_15_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aefdc6da05cfd4012097251989683d30f21626362c29463da121dc621046b2b6"
    hash2       = "36bbc80169bd128d160fb3869dcf23891b69a7765d8abb171897c9dfd0d58e3a"
    hash3       = "0ea76f5343284061fe91a1363d0a2116b76db249e7de5cc17a6971f30f805011"
    hash4       = "c25118c87134ffa298b9ec21b6abbfb10ced5f41dee519e34b593db27e0ce502"
    hash5       = "940de455f281b3225827ecddd883f1b43ba1368dbd7f57716d0a339045f24379"
    hash6       = "4f08e3a69121dfc3731f51c33e40cb14ff28c745c3471bd8ec1328cb7426f648"

  strings:
    $s1 = "CardSolver::CStateMachine::BuildChildStates - Hash collision" fullword wide
    $s2 = "Solver: SC=%d,MD=%d,MT=%d,PM=%d(A=%d)(" fullword wide
    $s3 = "Missing the Deck stack in the layout" fullword wide
    $s4 = "Unable to write classic score to the GameState node" fullword wide
    $s5 = "Couldn't find card for hint animation" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}