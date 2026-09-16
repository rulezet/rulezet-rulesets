rule TTP_XOR_QUAD_CurrentVersionRun_14de {
  strings:
    $key_14de = { 47 b1 [2] 63 bf [2] 48 93 [2] 66 b1 [2] 72 aa [2] 7d b0 [2] 63 ad [2] 61 ac [2] 7a aa [2] 66 ad [2] 7a 82 }

  condition:
    any of them
}