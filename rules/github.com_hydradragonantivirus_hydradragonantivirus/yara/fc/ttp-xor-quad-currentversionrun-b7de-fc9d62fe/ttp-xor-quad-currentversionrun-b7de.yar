rule TTP_XOR_QUAD_CurrentVersionRun_b7de {
  strings:
    $key_b7de = { e4 b1 [2] c0 bf [2] eb 93 [2] c5 b1 [2] d1 aa [2] de b0 [2] c0 ad [2] c2 ac [2] d9 aa [2] c5 ad [2] d9 82 }

  condition:
    any of them
}