rule TTP_XOR_QUAD_CurrentVersionRun_b256 {
  strings:
    $key_b256 = { e1 39 [2] c5 37 [2] ee 1b [2] c0 39 [2] d4 22 [2] db 38 [2] c5 25 [2] c7 24 [2] dc 22 [2] c0 25 [2] dc 0a }

  condition:
    any of them
}