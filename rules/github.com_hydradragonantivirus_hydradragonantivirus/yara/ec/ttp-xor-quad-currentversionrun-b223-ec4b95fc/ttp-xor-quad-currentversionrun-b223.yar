rule TTP_XOR_QUAD_CurrentVersionRun_b223 {
  strings:
    $key_b223 = { e1 4c [2] c5 42 [2] ee 6e [2] c0 4c [2] d4 57 [2] db 4d [2] c5 50 [2] c7 51 [2] dc 57 [2] c0 50 [2] dc 7f }

  condition:
    any of them
}