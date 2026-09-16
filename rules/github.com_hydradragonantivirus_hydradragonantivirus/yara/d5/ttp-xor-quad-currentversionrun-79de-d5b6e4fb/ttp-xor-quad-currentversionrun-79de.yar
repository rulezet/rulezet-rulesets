rule TTP_XOR_QUAD_CurrentVersionRun_79de {
  strings:
    $key_79de = { 2a b1 [2] 0e bf [2] 25 93 [2] 0b b1 [2] 1f aa [2] 10 b0 [2] 0e ad [2] 0c ac [2] 17 aa [2] 0b ad [2] 17 82 }

  condition:
    any of them
}