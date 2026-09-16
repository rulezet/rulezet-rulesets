rule TTP_XOR_QUAD_CurrentVersionRun_09cb {
  strings:
    $key_09cb = { 5a a4 [2] 7e aa [2] 55 86 [2] 7b a4 [2] 6f bf [2] 60 a5 [2] 7e b8 [2] 7c b9 [2] 67 bf [2] 7b b8 [2] 67 97 }

  condition:
    any of them
}