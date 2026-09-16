rule TTP_XOR_QUAD_CurrentVersionRun_b247 {
  strings:
    $key_b247 = { e1 28 [2] c5 26 [2] ee 0a [2] c0 28 [2] d4 33 [2] db 29 [2] c5 34 [2] c7 35 [2] dc 33 [2] c0 34 [2] dc 1b }

  condition:
    any of them
}