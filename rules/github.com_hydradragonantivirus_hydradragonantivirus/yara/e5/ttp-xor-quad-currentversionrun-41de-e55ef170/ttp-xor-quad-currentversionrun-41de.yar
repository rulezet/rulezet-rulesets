rule TTP_XOR_QUAD_CurrentVersionRun_41de {
  strings:
    $key_41de = { 12 b1 [2] 36 bf [2] 1d 93 [2] 33 b1 [2] 27 aa [2] 28 b0 [2] 36 ad [2] 34 ac [2] 2f aa [2] 33 ad [2] 2f 82 }

  condition:
    any of them
}