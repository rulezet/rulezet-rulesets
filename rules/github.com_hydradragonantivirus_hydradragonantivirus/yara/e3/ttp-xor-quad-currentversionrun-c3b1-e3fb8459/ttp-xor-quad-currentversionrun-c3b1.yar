rule TTP_XOR_QUAD_CurrentVersionRun_c3b1 {
  strings:
    $key_c3b1 = { 90 de [2] b4 d0 [2] 9f fc [2] b1 de [2] a5 c5 [2] aa df [2] b4 c2 [2] b6 c3 [2] ad c5 [2] b1 c2 [2] ad ed }

  condition:
    any of them
}