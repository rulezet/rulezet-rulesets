rule TTP_XOR_QUAD_CurrentVersionRun_b574 {
  strings:
    $key_b574 = { e6 1b [2] c2 15 [2] e9 39 [2] c7 1b [2] d3 00 [2] dc 1a [2] c2 07 [2] c0 06 [2] db 00 [2] c7 07 [2] db 28 }

  condition:
    any of them
}