rule TTP_XOR_QUAD_CurrentVersionRun_b55a {
  strings:
    $key_b55a = { e6 35 [2] c2 3b [2] e9 17 [2] c7 35 [2] d3 2e [2] dc 34 [2] c2 29 [2] c0 28 [2] db 2e [2] c7 29 [2] db 06 }

  condition:
    any of them
}