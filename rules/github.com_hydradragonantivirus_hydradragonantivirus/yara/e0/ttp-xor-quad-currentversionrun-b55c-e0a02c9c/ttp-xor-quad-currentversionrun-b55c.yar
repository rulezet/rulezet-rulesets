rule TTP_XOR_QUAD_CurrentVersionRun_b55c {
  strings:
    $key_b55c = { e6 33 [2] c2 3d [2] e9 11 [2] c7 33 [2] d3 28 [2] dc 32 [2] c2 2f [2] c0 2e [2] db 28 [2] c7 2f [2] db 00 }

  condition:
    any of them
}