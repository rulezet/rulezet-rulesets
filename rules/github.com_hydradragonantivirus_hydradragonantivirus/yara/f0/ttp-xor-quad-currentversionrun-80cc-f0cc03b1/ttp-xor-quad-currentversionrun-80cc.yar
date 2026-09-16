rule TTP_XOR_QUAD_CurrentVersionRun_80cc {
  strings:
    $key_80cc = { d3 a3 [2] f7 ad [2] dc 81 [2] f2 a3 [2] e6 b8 [2] e9 a2 [2] f7 bf [2] f5 be [2] ee b8 [2] f2 bf [2] ee 90 }

  condition:
    any of them
}