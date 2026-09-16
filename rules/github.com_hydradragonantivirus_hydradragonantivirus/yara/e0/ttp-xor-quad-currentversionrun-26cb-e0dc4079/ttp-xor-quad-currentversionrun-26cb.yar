rule TTP_XOR_QUAD_CurrentVersionRun_26cb {
  strings:
    $key_26cb = { 75 a4 [2] 51 aa [2] 7a 86 [2] 54 a4 [2] 40 bf [2] 4f a5 [2] 51 b8 [2] 53 b9 [2] 48 bf [2] 54 b8 [2] 48 97 }

  condition:
    any of them
}