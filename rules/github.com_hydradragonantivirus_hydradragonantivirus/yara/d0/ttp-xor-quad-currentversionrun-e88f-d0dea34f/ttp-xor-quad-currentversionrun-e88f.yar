rule TTP_XOR_QUAD_CurrentVersionRun_e88f {
  strings:
    $key_e88f = { bb e0 [2] 9f ee [2] b4 c2 [2] 9a e0 [2] 8e fb [2] 81 e1 [2] 9f fc [2] 9d fd [2] 86 fb [2] 9a fc [2] 86 d3 }

  condition:
    any of them
}