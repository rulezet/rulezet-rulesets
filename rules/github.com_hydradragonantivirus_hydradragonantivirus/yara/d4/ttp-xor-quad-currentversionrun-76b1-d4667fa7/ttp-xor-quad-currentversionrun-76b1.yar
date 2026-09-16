rule TTP_XOR_QUAD_CurrentVersionRun_76b1 {
  strings:
    $key_76b1 = { 25 de [2] 01 d0 [2] 2a fc [2] 04 de [2] 10 c5 [2] 1f df [2] 01 c2 [2] 03 c3 [2] 18 c5 [2] 04 c2 [2] 18 ed }

  condition:
    any of them
}