rule TTP_XOR_QUAD_CurrentVersionRun_05de {
  strings:
    $key_05de = { 56 b1 [2] 72 bf [2] 59 93 [2] 77 b1 [2] 63 aa [2] 6c b0 [2] 72 ad [2] 70 ac [2] 6b aa [2] 77 ad [2] 6b 82 }

  condition:
    any of them
}