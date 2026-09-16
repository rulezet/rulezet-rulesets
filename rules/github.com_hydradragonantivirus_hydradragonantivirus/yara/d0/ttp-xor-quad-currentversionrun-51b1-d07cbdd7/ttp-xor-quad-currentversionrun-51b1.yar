rule TTP_XOR_QUAD_CurrentVersionRun_51b1 {
  strings:
    $key_51b1 = { 02 de [2] 26 d0 [2] 0d fc [2] 23 de [2] 37 c5 [2] 38 df [2] 26 c2 [2] 24 c3 [2] 3f c5 [2] 23 c2 [2] 3f ed }

  condition:
    any of them
}