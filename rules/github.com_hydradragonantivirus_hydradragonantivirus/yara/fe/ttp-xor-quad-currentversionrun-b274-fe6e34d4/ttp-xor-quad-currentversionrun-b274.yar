rule TTP_XOR_QUAD_CurrentVersionRun_b274 {
  strings:
    $key_b274 = { e1 1b [2] c5 15 [2] ee 39 [2] c0 1b [2] d4 00 [2] db 1a [2] c5 07 [2] c7 06 [2] dc 00 [2] c0 07 [2] dc 28 }

  condition:
    any of them
}