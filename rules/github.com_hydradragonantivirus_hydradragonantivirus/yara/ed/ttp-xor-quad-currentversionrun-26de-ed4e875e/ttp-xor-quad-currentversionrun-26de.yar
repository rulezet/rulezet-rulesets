rule TTP_XOR_QUAD_CurrentVersionRun_26de {
  strings:
    $key_26de = { 75 b1 [2] 51 bf [2] 7a 93 [2] 54 b1 [2] 40 aa [2] 4f b0 [2] 51 ad [2] 53 ac [2] 48 aa [2] 54 ad [2] 48 82 }

  condition:
    any of them
}