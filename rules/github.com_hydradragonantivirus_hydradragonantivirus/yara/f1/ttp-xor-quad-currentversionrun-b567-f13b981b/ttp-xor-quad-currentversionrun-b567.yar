rule TTP_XOR_QUAD_CurrentVersionRun_b567 {
  strings:
    $key_b567 = { e6 08 [2] c2 06 [2] e9 2a [2] c7 08 [2] d3 13 [2] dc 09 [2] c2 14 [2] c0 15 [2] db 13 [2] c7 14 [2] db 3b }

  condition:
    any of them
}