rule TTP_XOR_QUAD_CurrentVersionRun_b2d7 {
  strings:
    $key_b2d7 = { e1 b8 [2] c5 b6 [2] ee 9a [2] c0 b8 [2] d4 a3 [2] db b9 [2] c5 a4 [2] c7 a5 [2] dc a3 [2] c0 a4 [2] dc 8b }

  condition:
    any of them
}