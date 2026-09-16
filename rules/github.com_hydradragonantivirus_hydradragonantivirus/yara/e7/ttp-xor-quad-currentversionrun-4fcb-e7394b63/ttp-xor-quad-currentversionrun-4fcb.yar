rule TTP_XOR_QUAD_CurrentVersionRun_4fcb {
  strings:
    $key_4fcb = { 1c a4 [2] 38 aa [2] 13 86 [2] 3d a4 [2] 29 bf [2] 26 a5 [2] 38 b8 [2] 3a b9 [2] 21 bf [2] 3d b8 [2] 21 97 }

  condition:
    any of them
}