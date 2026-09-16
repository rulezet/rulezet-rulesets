rule TTP_XOR_QUAD_CurrentVersionRun_fede {
  strings:
    $key_fede = { ad b1 [2] 89 bf [2] a2 93 [2] 8c b1 [2] 98 aa [2] 97 b0 [2] 89 ad [2] 8b ac [2] 90 aa [2] 8c ad [2] 90 82 }

  condition:
    any of them
}