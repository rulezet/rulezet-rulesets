rule TTP_XOR_QUAD_CurrentVersionRun_b57b {
  strings:
    $key_b57b = { e6 14 [2] c2 1a [2] e9 36 [2] c7 14 [2] d3 0f [2] dc 15 [2] c2 08 [2] c0 09 [2] db 0f [2] c7 08 [2] db 27 }

  condition:
    any of them
}