rule TTP_XOR_QUAD_CurrentVersionRun_f2de {
  strings:
    $key_f2de = { a1 b1 [2] 85 bf [2] ae 93 [2] 80 b1 [2] 94 aa [2] 9b b0 [2] 85 ad [2] 87 ac [2] 9c aa [2] 80 ad [2] 9c 82 }

  condition:
    any of them
}