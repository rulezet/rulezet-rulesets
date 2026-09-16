rule TTP_XOR_QUAD_CurrentVersionRun_24de {
  strings:
    $key_24de = { 77 b1 [2] 53 bf [2] 78 93 [2] 56 b1 [2] 42 aa [2] 4d b0 [2] 53 ad [2] 51 ac [2] 4a aa [2] 56 ad [2] 4a 82 }

  condition:
    any of them
}