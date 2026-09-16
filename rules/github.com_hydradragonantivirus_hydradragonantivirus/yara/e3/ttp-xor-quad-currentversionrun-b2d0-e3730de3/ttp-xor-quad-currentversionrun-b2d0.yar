rule TTP_XOR_QUAD_CurrentVersionRun_b2d0 {
  strings:
    $key_b2d0 = { e1 bf [2] c5 b1 [2] ee 9d [2] c0 bf [2] d4 a4 [2] db be [2] c5 a3 [2] c7 a2 [2] dc a4 [2] c0 a3 [2] dc 8c }

  condition:
    any of them
}