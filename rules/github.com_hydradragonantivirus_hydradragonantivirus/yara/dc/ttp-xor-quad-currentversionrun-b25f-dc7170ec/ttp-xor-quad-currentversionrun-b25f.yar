rule TTP_XOR_QUAD_CurrentVersionRun_b25f {
  strings:
    $key_b25f = { e1 30 [2] c5 3e [2] ee 12 [2] c0 30 [2] d4 2b [2] db 31 [2] c5 2c [2] c7 2d [2] dc 2b [2] c0 2c [2] dc 03 }

  condition:
    any of them
}