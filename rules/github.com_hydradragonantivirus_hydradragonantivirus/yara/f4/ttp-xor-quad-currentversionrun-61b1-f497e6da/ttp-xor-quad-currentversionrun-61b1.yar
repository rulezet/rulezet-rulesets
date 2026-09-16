rule TTP_XOR_QUAD_CurrentVersionRun_61b1 {
  strings:
    $key_61b1 = { 32 de [2] 16 d0 [2] 3d fc [2] 13 de [2] 07 c5 [2] 08 df [2] 16 c2 [2] 14 c3 [2] 0f c5 [2] 13 c2 [2] 0f ed }

  condition:
    any of them
}