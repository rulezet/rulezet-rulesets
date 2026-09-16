rule TTP_XOR_QUAD_CurrentVersionRun_b273 {
  strings:
    $key_b273 = { e1 1c [2] c5 12 [2] ee 3e [2] c0 1c [2] d4 07 [2] db 1d [2] c5 00 [2] c7 01 [2] dc 07 [2] c0 00 [2] dc 2f }

  condition:
    any of them
}