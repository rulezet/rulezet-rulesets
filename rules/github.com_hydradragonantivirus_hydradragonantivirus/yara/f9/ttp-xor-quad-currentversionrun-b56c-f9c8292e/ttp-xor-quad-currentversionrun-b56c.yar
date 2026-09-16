rule TTP_XOR_QUAD_CurrentVersionRun_b56c {
  strings:
    $key_b56c = { e6 03 [2] c2 0d [2] e9 21 [2] c7 03 [2] d3 18 [2] dc 02 [2] c2 1f [2] c0 1e [2] db 18 [2] c7 1f [2] db 30 }

  condition:
    any of them
}