rule TTP_XOR_QUAD_CurrentVersionRun_b27c {
  strings:
    $key_b27c = { e1 13 [2] c5 1d [2] ee 31 [2] c0 13 [2] d4 08 [2] db 12 [2] c5 0f [2] c7 0e [2] dc 08 [2] c0 0f [2] dc 20 }

  condition:
    any of them
}