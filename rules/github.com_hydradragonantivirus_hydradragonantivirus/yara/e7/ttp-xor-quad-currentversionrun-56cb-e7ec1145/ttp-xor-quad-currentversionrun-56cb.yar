rule TTP_XOR_QUAD_CurrentVersionRun_56cb {
  strings:
    $key_56cb = { 05 a4 [2] 21 aa [2] 0a 86 [2] 24 a4 [2] 30 bf [2] 3f a5 [2] 21 b8 [2] 23 b9 [2] 38 bf [2] 24 b8 [2] 38 97 }

  condition:
    any of them
}