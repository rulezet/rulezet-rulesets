rule TTP_XOR_QUAD_CurrentVersionRun_7ccb {
  strings:
    $key_7ccb = { 2f a4 [2] 0b aa [2] 20 86 [2] 0e a4 [2] 1a bf [2] 15 a5 [2] 0b b8 [2] 09 b9 [2] 12 bf [2] 0e b8 [2] 12 97 }

  condition:
    any of them
}