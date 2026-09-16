rule TTP_XOR_QUAD_CurrentVersionRun_b553 {
  strings:
    $key_b553 = { e6 3c [2] c2 32 [2] e9 1e [2] c7 3c [2] d3 27 [2] dc 3d [2] c2 20 [2] c0 21 [2] db 27 [2] c7 20 [2] db 0f }

  condition:
    any of them
}