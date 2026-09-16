rule TTP_XOR_QUAD_CurrentVersionRun_b22b {
  strings:
    $key_b22b = { e1 44 [2] c5 4a [2] ee 66 [2] c0 44 [2] d4 5f [2] db 45 [2] c5 58 [2] c7 59 [2] dc 5f [2] c0 58 [2] dc 77 }

  condition:
    any of them
}