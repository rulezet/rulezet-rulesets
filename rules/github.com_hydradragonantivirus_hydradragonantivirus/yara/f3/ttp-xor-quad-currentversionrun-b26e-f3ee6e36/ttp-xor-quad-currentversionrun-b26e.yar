rule TTP_XOR_QUAD_CurrentVersionRun_b26e {
  strings:
    $key_b26e = { e1 01 [2] c5 0f [2] ee 23 [2] c0 01 [2] d4 1a [2] db 00 [2] c5 1d [2] c7 1c [2] dc 1a [2] c0 1d [2] dc 32 }

  condition:
    any of them
}