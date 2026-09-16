rule TTP_XOR_QUAD_CurrentVersionRun_b550 {
  strings:
    $key_b550 = { e6 3f [2] c2 31 [2] e9 1d [2] c7 3f [2] d3 24 [2] dc 3e [2] c2 23 [2] c0 22 [2] db 24 [2] c7 23 [2] db 0c }

  condition:
    any of them
}