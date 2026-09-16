rule TTP_XOR_QUAD_CurrentVersionRun_b561 {
  strings:
    $key_b561 = { e6 0e [2] c2 00 [2] e9 2c [2] c7 0e [2] d3 15 [2] dc 0f [2] c2 12 [2] c0 13 [2] db 15 [2] c7 12 [2] db 3d }

  condition:
    any of them
}