rule TTP_XOR_QUAD_CurrentVersionRun_79cb {
  strings:
    $key_79cb = { 2a a4 [2] 0e aa [2] 25 86 [2] 0b a4 [2] 1f bf [2] 10 a5 [2] 0e b8 [2] 0c b9 [2] 17 bf [2] 0b b8 [2] 17 97 }

  condition:
    any of them
}