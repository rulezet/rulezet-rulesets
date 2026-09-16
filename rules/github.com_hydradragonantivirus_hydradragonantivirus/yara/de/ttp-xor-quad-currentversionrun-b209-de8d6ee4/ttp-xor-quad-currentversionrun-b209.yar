rule TTP_XOR_QUAD_CurrentVersionRun_b209 {
  strings:
    $key_b209 = { e1 66 [2] c5 68 [2] ee 44 [2] c0 66 [2] d4 7d [2] db 67 [2] c5 7a [2] c7 7b [2] dc 7d [2] c0 7a [2] dc 55 }

  condition:
    any of them
}