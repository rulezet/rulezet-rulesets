rule TTP_XOR_QUAD_CurrentVersionRun_b2db {
  strings:
    $key_b2db = { e1 b4 [2] c5 ba [2] ee 96 [2] c0 b4 [2] d4 af [2] db b5 [2] c5 a8 [2] c7 a9 [2] dc af [2] c0 a8 [2] dc 87 }

  condition:
    any of them
}