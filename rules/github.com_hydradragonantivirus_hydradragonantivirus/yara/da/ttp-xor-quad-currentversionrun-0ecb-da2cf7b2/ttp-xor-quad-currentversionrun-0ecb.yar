rule TTP_XOR_QUAD_CurrentVersionRun_0ecb {
  strings:
    $key_0ecb = { 5d a4 [2] 79 aa [2] 52 86 [2] 7c a4 [2] 68 bf [2] 67 a5 [2] 79 b8 [2] 7b b9 [2] 60 bf [2] 7c b8 [2] 60 97 }

  condition:
    any of them
}