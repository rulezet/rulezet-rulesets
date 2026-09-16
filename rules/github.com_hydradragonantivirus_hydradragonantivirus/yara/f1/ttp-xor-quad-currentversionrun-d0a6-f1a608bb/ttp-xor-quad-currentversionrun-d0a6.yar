rule TTP_XOR_QUAD_CurrentVersionRun_d0a6 {
  strings:
    $key_d0a6 = { 83 c9 [2] a7 c7 [2] 8c eb [2] a2 c9 [2] b6 d2 [2] b9 c8 [2] a7 d5 [2] a5 d4 [2] be d2 [2] a2 d5 [2] be fa }

  condition:
    any of them
}