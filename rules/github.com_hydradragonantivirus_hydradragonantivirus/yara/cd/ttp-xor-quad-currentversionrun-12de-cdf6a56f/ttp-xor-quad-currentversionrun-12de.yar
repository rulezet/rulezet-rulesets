rule TTP_XOR_QUAD_CurrentVersionRun_12de {
  strings:
    $key_12de = { 41 b1 [2] 65 bf [2] 4e 93 [2] 60 b1 [2] 74 aa [2] 7b b0 [2] 65 ad [2] 67 ac [2] 7c aa [2] 60 ad [2] 7c 82 }

  condition:
    any of them
}