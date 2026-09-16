rule TTP_XOR_QUAD_CurrentVersionRun_b2c0 {
  strings:
    $key_b2c0 = { e1 af [2] c5 a1 [2] ee 8d [2] c0 af [2] d4 b4 [2] db ae [2] c5 b3 [2] c7 b2 [2] dc b4 [2] c0 b3 [2] dc 9c }

  condition:
    any of them
}