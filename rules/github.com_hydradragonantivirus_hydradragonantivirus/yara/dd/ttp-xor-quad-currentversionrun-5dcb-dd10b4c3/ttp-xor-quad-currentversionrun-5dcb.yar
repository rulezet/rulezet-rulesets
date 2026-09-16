rule TTP_XOR_QUAD_CurrentVersionRun_5dcb {
  strings:
    $key_5dcb = { 0e a4 [2] 2a aa [2] 01 86 [2] 2f a4 [2] 3b bf [2] 34 a5 [2] 2a b8 [2] 28 b9 [2] 33 bf [2] 2f b8 [2] 33 97 }

  condition:
    any of them
}