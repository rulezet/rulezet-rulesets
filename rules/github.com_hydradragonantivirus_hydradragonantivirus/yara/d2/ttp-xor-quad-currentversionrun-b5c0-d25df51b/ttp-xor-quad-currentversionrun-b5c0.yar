rule TTP_XOR_QUAD_CurrentVersionRun_b5c0 {
  strings:
    $key_b5c0 = { e6 af [2] c2 a1 [2] e9 8d [2] c7 af [2] d3 b4 [2] dc ae [2] c2 b3 [2] c0 b2 [2] db b4 [2] c7 b3 [2] db 9c }

  condition:
    any of them
}