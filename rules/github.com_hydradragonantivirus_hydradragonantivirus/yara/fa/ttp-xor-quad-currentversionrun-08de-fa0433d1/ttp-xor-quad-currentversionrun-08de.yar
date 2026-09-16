rule TTP_XOR_QUAD_CurrentVersionRun_08de {
  strings:
    $key_08de = { 5b b1 [2] 7f bf [2] 54 93 [2] 7a b1 [2] 6e aa [2] 61 b0 [2] 7f ad [2] 7d ac [2] 66 aa [2] 7a ad [2] 66 82 }

  condition:
    any of them
}