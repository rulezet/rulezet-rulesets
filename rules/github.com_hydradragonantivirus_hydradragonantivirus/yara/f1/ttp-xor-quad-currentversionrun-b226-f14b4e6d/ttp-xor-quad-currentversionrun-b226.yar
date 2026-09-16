rule TTP_XOR_QUAD_CurrentVersionRun_b226 {
  strings:
    $key_b226 = { e1 49 [2] c5 47 [2] ee 6b [2] c0 49 [2] d4 52 [2] db 48 [2] c5 55 [2] c7 54 [2] dc 52 [2] c0 55 [2] dc 7a }

  condition:
    any of them
}