rule TTP_XOR_QUAD_CurrentVersionRun_b5c6 {
  strings:
    $key_b5c6 = { e6 a9 [2] c2 a7 [2] e9 8b [2] c7 a9 [2] d3 b2 [2] dc a8 [2] c2 b5 [2] c0 b4 [2] db b2 [2] c7 b5 [2] db 9a }

  condition:
    any of them
}