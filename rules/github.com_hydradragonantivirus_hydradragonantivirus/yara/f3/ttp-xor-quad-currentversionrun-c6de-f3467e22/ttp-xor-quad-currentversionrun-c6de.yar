rule TTP_XOR_QUAD_CurrentVersionRun_c6de {
  strings:
    $key_c6de = { 95 b1 [2] b1 bf [2] 9a 93 [2] b4 b1 [2] a0 aa [2] af b0 [2] b1 ad [2] b3 ac [2] a8 aa [2] b4 ad [2] a8 82 }

  condition:
    any of them
}