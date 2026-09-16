rule TTP_XOR_QUAD_CurrentVersionRun_3ccb {
  strings:
    $key_3ccb = { 6f a4 [2] 4b aa [2] 60 86 [2] 4e a4 [2] 5a bf [2] 55 a5 [2] 4b b8 [2] 49 b9 [2] 52 bf [2] 4e b8 [2] 52 97 }

  condition:
    any of them
}