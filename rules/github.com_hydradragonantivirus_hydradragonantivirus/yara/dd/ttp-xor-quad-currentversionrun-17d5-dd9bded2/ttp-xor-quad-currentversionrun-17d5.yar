rule TTP_XOR_QUAD_CurrentVersionRun_17d5 {
  strings:
    $key_17d5 = { 44 ba [2] 60 b4 [2] 4b 98 [2] 65 ba [2] 71 a1 [2] 7e bb [2] 60 a6 [2] 62 a7 [2] 79 a1 [2] 65 a6 [2] 79 89 }

  condition:
    any of them
}