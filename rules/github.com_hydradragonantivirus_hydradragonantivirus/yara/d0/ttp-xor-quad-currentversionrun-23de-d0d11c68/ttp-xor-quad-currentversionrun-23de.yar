rule TTP_XOR_QUAD_CurrentVersionRun_23de {
  strings:
    $key_23de = { 70 b1 [2] 54 bf [2] 7f 93 [2] 51 b1 [2] 45 aa [2] 4a b0 [2] 54 ad [2] 56 ac [2] 4d aa [2] 51 ad [2] 4d 82 }

  condition:
    any of them
}