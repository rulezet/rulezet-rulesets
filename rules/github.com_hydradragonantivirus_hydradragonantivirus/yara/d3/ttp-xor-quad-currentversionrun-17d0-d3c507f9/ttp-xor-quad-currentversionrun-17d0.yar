rule TTP_XOR_QUAD_CurrentVersionRun_17d0 {
  strings:
    $key_17d0 = { 44 bf [2] 60 b1 [2] 4b 9d [2] 65 bf [2] 71 a4 [2] 7e be [2] 60 a3 [2] 62 a2 [2] 79 a4 [2] 65 a3 [2] 79 8c }

  condition:
    any of them
}