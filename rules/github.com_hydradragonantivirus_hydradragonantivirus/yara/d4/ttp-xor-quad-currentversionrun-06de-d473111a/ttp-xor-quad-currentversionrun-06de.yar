rule TTP_XOR_QUAD_CurrentVersionRun_06de {
  strings:
    $key_06de = { 55 b1 [2] 71 bf [2] 5a 93 [2] 74 b1 [2] 60 aa [2] 6f b0 [2] 71 ad [2] 73 ac [2] 68 aa [2] 74 ad [2] 68 82 }

  condition:
    any of them
}