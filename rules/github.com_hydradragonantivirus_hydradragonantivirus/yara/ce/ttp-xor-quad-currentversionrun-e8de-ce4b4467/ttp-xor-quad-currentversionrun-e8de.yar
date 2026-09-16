rule TTP_XOR_QUAD_CurrentVersionRun_e8de {
  strings:
    $key_e8de = { bb b1 [2] 9f bf [2] b4 93 [2] 9a b1 [2] 8e aa [2] 81 b0 [2] 9f ad [2] 9d ac [2] 86 aa [2] 9a ad [2] 86 82 }

  condition:
    any of them
}