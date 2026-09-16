rule TTP_XOR_QUAD_CurrentVersionRun_40de {
  strings:
    $key_40de = { 13 b1 [2] 37 bf [2] 1c 93 [2] 32 b1 [2] 26 aa [2] 29 b0 [2] 37 ad [2] 35 ac [2] 2e aa [2] 32 ad [2] 2e 82 }

  condition:
    any of them
}