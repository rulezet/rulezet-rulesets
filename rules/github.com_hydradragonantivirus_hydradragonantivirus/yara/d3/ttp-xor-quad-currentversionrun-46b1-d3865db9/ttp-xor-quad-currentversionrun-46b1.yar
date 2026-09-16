rule TTP_XOR_QUAD_CurrentVersionRun_46b1 {
  strings:
    $key_46b1 = { 15 de [2] 31 d0 [2] 1a fc [2] 34 de [2] 20 c5 [2] 2f df [2] 31 c2 [2] 33 c3 [2] 28 c5 [2] 34 c2 [2] 28 ed }

  condition:
    any of them
}