rule TTP_XOR_QUAD_CurrentVersionRun_68de {
  strings:
    $key_68de = { 3b b1 [2] 1f bf [2] 34 93 [2] 1a b1 [2] 0e aa [2] 01 b0 [2] 1f ad [2] 1d ac [2] 06 aa [2] 1a ad [2] 06 82 }

  condition:
    any of them
}