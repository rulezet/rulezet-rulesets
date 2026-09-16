rule TTP_XOR_QUAD_CurrentVersionRun_3ecb {
  strings:
    $key_3ecb = { 6d a4 [2] 49 aa [2] 62 86 [2] 4c a4 [2] 58 bf [2] 57 a5 [2] 49 b8 [2] 4b b9 [2] 50 bf [2] 4c b8 [2] 50 97 }

  condition:
    any of them
}