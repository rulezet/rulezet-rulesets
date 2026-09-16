rule TTP_XOR_QUAD_CurrentVersionRun_39cb {
  strings:
    $key_39cb = { 6a a4 [2] 4e aa [2] 65 86 [2] 4b a4 [2] 5f bf [2] 50 a5 [2] 4e b8 [2] 4c b9 [2] 57 bf [2] 4b b8 [2] 57 97 }

  condition:
    any of them
}