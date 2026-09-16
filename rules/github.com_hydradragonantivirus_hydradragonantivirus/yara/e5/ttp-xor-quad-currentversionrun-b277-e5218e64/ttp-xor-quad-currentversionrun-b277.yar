rule TTP_XOR_QUAD_CurrentVersionRun_b277 {
  strings:
    $key_b277 = { e1 18 [2] c5 16 [2] ee 3a [2] c0 18 [2] d4 03 [2] db 19 [2] c5 04 [2] c7 05 [2] dc 03 [2] c0 04 [2] dc 2b }

  condition:
    any of them
}