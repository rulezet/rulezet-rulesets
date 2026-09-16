rule TTP_XOR_QUAD_CurrentVersionRun_b573 {
  strings:
    $key_b573 = { e6 1c [2] c2 12 [2] e9 3e [2] c7 1c [2] d3 07 [2] dc 1d [2] c2 00 [2] c0 01 [2] db 07 [2] c7 00 [2] db 2f }

  condition:
    any of them
}