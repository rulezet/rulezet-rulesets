rule TTP_XOR_QUAD_CurrentVersionRun_b54b {
  strings:
    $key_b54b = { e6 24 [2] c2 2a [2] e9 06 [2] c7 24 [2] d3 3f [2] dc 25 [2] c2 38 [2] c0 39 [2] db 3f [2] c7 38 [2] db 17 }

  condition:
    any of them
}