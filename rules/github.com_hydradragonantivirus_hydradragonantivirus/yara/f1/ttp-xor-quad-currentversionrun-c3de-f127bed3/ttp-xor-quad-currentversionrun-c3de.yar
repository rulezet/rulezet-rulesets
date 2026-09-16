rule TTP_XOR_QUAD_CurrentVersionRun_c3de {
  strings:
    $key_c3de = { 90 b1 [2] b4 bf [2] 9f 93 [2] b1 b1 [2] a5 aa [2] aa b0 [2] b4 ad [2] b6 ac [2] ad aa [2] b1 ad [2] ad 82 }

  condition:
    any of them
}