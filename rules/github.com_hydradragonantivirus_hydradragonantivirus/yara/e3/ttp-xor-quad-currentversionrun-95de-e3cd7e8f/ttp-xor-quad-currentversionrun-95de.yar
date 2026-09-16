rule TTP_XOR_QUAD_CurrentVersionRun_95de {
  strings:
    $key_95de = { c6 b1 [2] e2 bf [2] c9 93 [2] e7 b1 [2] f3 aa [2] fc b0 [2] e2 ad [2] e0 ac [2] fb aa [2] e7 ad [2] fb 82 }

  condition:
    any of them
}