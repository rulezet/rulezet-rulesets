rule TTP_XOR_QUAD_CurrentVersionRun_b225 {
  strings:
    $key_b225 = { e1 4a [2] c5 44 [2] ee 68 [2] c0 4a [2] d4 51 [2] db 4b [2] c5 56 [2] c7 57 [2] dc 51 [2] c0 56 [2] dc 79 }

  condition:
    any of them
}