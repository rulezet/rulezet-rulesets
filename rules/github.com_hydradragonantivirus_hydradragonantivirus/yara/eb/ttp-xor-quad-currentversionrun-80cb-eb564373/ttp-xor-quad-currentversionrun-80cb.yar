rule TTP_XOR_QUAD_CurrentVersionRun_80cb {
  strings:
    $key_80cb = { d3 a4 [2] f7 aa [2] dc 86 [2] f2 a4 [2] e6 bf [2] e9 a5 [2] f7 b8 [2] f5 b9 [2] ee bf [2] f2 b8 [2] ee 97 }

  condition:
    any of them
}