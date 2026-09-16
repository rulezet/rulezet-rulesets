rule TTP_XOR_QUAD_CurrentVersionRun_c1de {
  strings:
    $key_c1de = { 92 b1 [2] b6 bf [2] 9d 93 [2] b3 b1 [2] a7 aa [2] a8 b0 [2] b6 ad [2] b4 ac [2] af aa [2] b3 ad [2] af 82 }

  condition:
    any of them
}