rule TTP_XOR_QUAD_CurrentVersionRun_b2c2 {
  strings:
    $key_b2c2 = { e1 ad [2] c5 a3 [2] ee 8f [2] c0 ad [2] d4 b6 [2] db ac [2] c5 b1 [2] c7 b0 [2] dc b6 [2] c0 b1 [2] dc 9e }

  condition:
    any of them
}