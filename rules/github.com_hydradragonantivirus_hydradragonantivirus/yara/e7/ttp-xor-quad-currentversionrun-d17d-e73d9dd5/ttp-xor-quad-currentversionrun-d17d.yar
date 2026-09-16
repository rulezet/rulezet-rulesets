rule TTP_XOR_QUAD_CurrentVersionRun_d17d {
  strings:
    $key_d17d = { 82 12 [2] a6 1c [2] 8d 30 [2] a3 12 [2] b7 09 [2] b8 13 [2] a6 0e [2] a4 0f [2] bf 09 [2] a3 0e [2] bf 21 }

  condition:
    any of them
}