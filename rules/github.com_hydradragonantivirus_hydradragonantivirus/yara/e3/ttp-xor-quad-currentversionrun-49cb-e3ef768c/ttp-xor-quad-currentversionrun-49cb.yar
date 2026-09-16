rule TTP_XOR_QUAD_CurrentVersionRun_49cb {
  strings:
    $key_49cb = { 1a a4 [2] 3e aa [2] 15 86 [2] 3b a4 [2] 2f bf [2] 20 a5 [2] 3e b8 [2] 3c b9 [2] 27 bf [2] 3b b8 [2] 27 97 }

  condition:
    any of them
}