rule TTP_XOR_QUAD_CurrentVersionRun_b1de {
  strings:
    $key_b1de = { e2 b1 [2] c6 bf [2] ed 93 [2] c3 b1 [2] d7 aa [2] d8 b0 [2] c6 ad [2] c4 ac [2] df aa [2] c3 ad [2] df 82 }

  condition:
    any of them
}