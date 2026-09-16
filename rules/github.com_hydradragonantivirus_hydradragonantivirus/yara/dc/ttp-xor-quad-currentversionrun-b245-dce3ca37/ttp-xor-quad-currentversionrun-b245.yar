rule TTP_XOR_QUAD_CurrentVersionRun_b245 {
  strings:
    $key_b245 = { e1 2a [2] c5 24 [2] ee 08 [2] c0 2a [2] d4 31 [2] db 2b [2] c5 36 [2] c7 37 [2] dc 31 [2] c0 36 [2] dc 19 }

  condition:
    any of them
}