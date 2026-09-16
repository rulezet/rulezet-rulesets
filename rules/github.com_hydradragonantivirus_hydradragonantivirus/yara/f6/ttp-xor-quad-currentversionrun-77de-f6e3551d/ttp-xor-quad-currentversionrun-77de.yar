rule TTP_XOR_QUAD_CurrentVersionRun_77de {
  strings:
    $key_77de = { 24 b1 [2] 00 bf [2] 2b 93 [2] 05 b1 [2] 11 aa [2] 1e b0 [2] 00 ad [2] 02 ac [2] 19 aa [2] 05 ad [2] 19 82 }

  condition:
    any of them
}