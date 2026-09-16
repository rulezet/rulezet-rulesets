rule TTP_XOR_QUAD_CurrentVersionRun_b547 {
  strings:
    $key_b547 = { e6 28 [2] c2 26 [2] e9 0a [2] c7 28 [2] d3 33 [2] dc 29 [2] c2 34 [2] c0 35 [2] db 33 [2] c7 34 [2] db 1b }

  condition:
    any of them
}