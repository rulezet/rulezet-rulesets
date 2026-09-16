rule TTP_XOR_QUAD_CurrentVersionRun_b54d {
  strings:
    $key_b54d = { e6 22 [2] c2 2c [2] e9 00 [2] c7 22 [2] d3 39 [2] dc 23 [2] c2 3e [2] c0 3f [2] db 39 [2] c7 3e [2] db 11 }

  condition:
    any of them
}