rule TTP_XOR_QUAD_CurrentVersionRun_b2c1 {
  strings:
    $key_b2c1 = { e1 ae [2] c5 a0 [2] ee 8c [2] c0 ae [2] d4 b5 [2] db af [2] c5 b2 [2] c7 b3 [2] dc b5 [2] c0 b2 [2] dc 9d }

  condition:
    any of them
}