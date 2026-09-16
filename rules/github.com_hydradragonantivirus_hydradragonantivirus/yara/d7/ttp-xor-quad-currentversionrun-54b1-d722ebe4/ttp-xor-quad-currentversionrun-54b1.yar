rule TTP_XOR_QUAD_CurrentVersionRun_54b1 {
  strings:
    $key_54b1 = { 07 de [2] 23 d0 [2] 08 fc [2] 26 de [2] 32 c5 [2] 3d df [2] 23 c2 [2] 21 c3 [2] 3a c5 [2] 26 c2 [2] 3a ed }

  condition:
    any of them
}