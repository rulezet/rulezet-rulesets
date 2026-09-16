rule TTP_XOR_QUAD_CurrentVersionRun_b51d {
  strings:
    $key_b51d = { e6 72 [2] c2 7c [2] e9 50 [2] c7 72 [2] d3 69 [2] dc 73 [2] c2 6e [2] c0 6f [2] db 69 [2] c7 6e [2] db 41 }

  condition:
    any of them
}