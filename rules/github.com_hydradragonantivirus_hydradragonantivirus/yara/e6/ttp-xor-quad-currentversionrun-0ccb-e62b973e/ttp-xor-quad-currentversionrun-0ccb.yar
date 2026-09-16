rule TTP_XOR_QUAD_CurrentVersionRun_0ccb {
  strings:
    $key_0ccb = { 5f a4 [2] 7b aa [2] 50 86 [2] 7e a4 [2] 6a bf [2] 65 a5 [2] 7b b8 [2] 79 b9 [2] 62 bf [2] 7e b8 [2] 62 97 }

  condition:
    any of them
}