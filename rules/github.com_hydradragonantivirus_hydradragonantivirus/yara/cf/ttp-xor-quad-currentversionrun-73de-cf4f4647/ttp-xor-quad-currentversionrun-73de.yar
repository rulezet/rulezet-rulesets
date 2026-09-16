rule TTP_XOR_QUAD_CurrentVersionRun_73de {
  strings:
    $key_73de = { 20 b1 [2] 04 bf [2] 2f 93 [2] 01 b1 [2] 15 aa [2] 1a b0 [2] 04 ad [2] 06 ac [2] 1d aa [2] 01 ad [2] 1d 82 }

  condition:
    any of them
}