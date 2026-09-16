rule TTP_XOR_QUAD_CurrentVersionRun_688f {
  strings:
    $key_688f = { 3b e0 [2] 1f ee [2] 34 c2 [2] 1a e0 [2] 0e fb [2] 01 e1 [2] 1f fc [2] 1d fd [2] 06 fb [2] 1a fc [2] 06 d3 }

  condition:
    any of them
}