rule TTP_XOR_QUAD_CurrentVersionRun_b263 {
  strings:
    $key_b263 = { e1 0c [2] c5 02 [2] ee 2e [2] c0 0c [2] d4 17 [2] db 0d [2] c5 10 [2] c7 11 [2] dc 17 [2] c0 10 [2] dc 3f }

  condition:
    any of them
}