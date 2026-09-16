rule TTP_XOR_QUAD_CurrentVersionRun_b2d1 {
  strings:
    $key_b2d1 = { e1 be [2] c5 b0 [2] ee 9c [2] c0 be [2] d4 a5 [2] db bf [2] c5 a2 [2] c7 a3 [2] dc a5 [2] c0 a2 [2] dc 8d }

  condition:
    any of them
}