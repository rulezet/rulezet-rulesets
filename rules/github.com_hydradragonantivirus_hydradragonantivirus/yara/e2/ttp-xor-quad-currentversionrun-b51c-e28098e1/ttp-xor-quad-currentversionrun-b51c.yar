rule TTP_XOR_QUAD_CurrentVersionRun_b51c {
  strings:
    $key_b51c = { e6 73 [2] c2 7d [2] e9 51 [2] c7 73 [2] d3 68 [2] dc 72 [2] c2 6f [2] c0 6e [2] db 68 [2] c7 6f [2] db 40 }

  condition:
    any of them
}