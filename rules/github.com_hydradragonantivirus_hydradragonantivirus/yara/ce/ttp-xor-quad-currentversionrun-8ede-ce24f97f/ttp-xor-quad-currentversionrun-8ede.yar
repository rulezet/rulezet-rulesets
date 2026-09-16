rule TTP_XOR_QUAD_CurrentVersionRun_8ede {
  strings:
    $key_8ede = { dd b1 [2] f9 bf [2] d2 93 [2] fc b1 [2] e8 aa [2] e7 b0 [2] f9 ad [2] fb ac [2] e0 aa [2] fc ad [2] e0 82 }

  condition:
    any of them
}