rule TTP_XOR_QUAD_CurrentVersionRun_eede {
  strings:
    $key_eede = { bd b1 [2] 99 bf [2] b2 93 [2] 9c b1 [2] 88 aa [2] 87 b0 [2] 99 ad [2] 9b ac [2] 80 aa [2] 9c ad [2] 80 82 }

  condition:
    any of them
}