rule TTP_XOR_QUAD_CurrentVersionRun_34de {
  strings:
    $key_34de = { 67 b1 [2] 43 bf [2] 68 93 [2] 46 b1 [2] 52 aa [2] 5d b0 [2] 43 ad [2] 41 ac [2] 5a aa [2] 46 ad [2] 5a 82 }

  condition:
    any of them
}