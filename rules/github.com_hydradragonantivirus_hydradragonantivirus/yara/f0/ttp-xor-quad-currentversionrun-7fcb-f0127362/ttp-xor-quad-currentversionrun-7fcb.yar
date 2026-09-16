rule TTP_XOR_QUAD_CurrentVersionRun_7fcb {
  strings:
    $key_7fcb = { 2c a4 [2] 08 aa [2] 23 86 [2] 0d a4 [2] 19 bf [2] 16 a5 [2] 08 b8 [2] 0a b9 [2] 11 bf [2] 0d b8 [2] 11 97 }

  condition:
    any of them
}