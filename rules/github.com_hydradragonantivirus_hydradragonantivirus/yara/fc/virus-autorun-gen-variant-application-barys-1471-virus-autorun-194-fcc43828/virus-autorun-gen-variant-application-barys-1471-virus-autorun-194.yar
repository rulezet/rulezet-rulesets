import "pe"
rule _Virus_Autorun_Gen_Variant_Application_Barys_1471_Virus_Autorun__194 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Variant.Application.Barys.1471.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36bbc80169bd128d160fb3869dcf23891b69a7765d8abb171897c9dfd0d58e3a"
    hash2       = "0ea76f5343284061fe91a1363d0a2116b76db249e7de5cc17a6971f30f805011"
    hash3       = "c25118c87134ffa298b9ec21b6abbfb10ced5f41dee519e34b593db27e0ce502"
    hash4       = "4f08e3a69121dfc3731f51c33e40cb14ff28c745c3471bd8ec1328cb7426f648"

  strings:
    $s1  = "|60220|UI_STATS|Spider Solitaire Statistics - %1//statistics dialog title (with username)" fullword wide
    $s2  = "Executable for Spider Solitaire Game" fullword wide
    $s3  = "SpiderOptions::FromXml() - Obsolete version found, recreating" fullword wide
    $s4  = "SpiderGame::ModifyScore() - Std Scoring: Update score %d + %d" fullword wide
    $s5  = "SpiderGame::PopState() - Std Scoring: Update score %d - %d" fullword wide
    $s6  = "SpiderGame::ModifyScore() - Std Scoring: Set CountAsMove to true" fullword wide
    $s7  = "CreateHints(): Unable to find hints with stacks ranking high, retry -- %d, cards observed: %d" fullword wide
    $s8  = "SpiderGame::OnCardDragStarted() - Card should belong to stack named %s, not %s" fullword wide
    $s9  = "|41806|UI_STATS|Spider Solitaire Statistics//statistics dialog title (no username)" fullword wide
    $s10 = "SpiderStatistics::FromXml() - NULL source xml." fullword wide
    $s11 = "SpiderStatistics::FromXml() - Incorrect number of score entries" fullword wide
    $s12 = "SpiderStatistics::FromXml() - Incorrect number of date entries" fullword wide
    $s13 = "SpiderStatistics::ToXml() - NULL parent tag." fullword wide
    $s14 = "SpiderOptions::FromXml() - NULL source xml." fullword wide
    $s15 = "SpiderOptions::ToXml() - NULL parent tag." fullword wide
    $s16 = "SpiderGameState::FromXml() - NULL source xml." fullword wide
    $s17 = "SpiderGameState::ToXml() - NULL parent tag." fullword wide
    $s18 = "Failed to get the spider layout xml" fullword wide
    $s19 = "SpiderGame::RequestDeal() - Tried to deal when no deck left" fullword wide
    $s20 = "SpiderGame::OnDeckClicked() - Tried to deal when no deck left" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "b941ddedcc51e5706d41335adb4e6b2a" and (8 of them)
    ) or (all of them)
}