rule TTP_XOR_QUAD_CurrentVersionRun_b24b {
  strings:
    $key_b24b = { e1 24 [2] c5 2a [2] ee 06 [2] c0 24 [2] d4 3f [2] db 25 [2] c5 38 [2] c7 39 [2] dc 3f [2] c0 38 [2] dc 17 }

  condition:
    any of them
}