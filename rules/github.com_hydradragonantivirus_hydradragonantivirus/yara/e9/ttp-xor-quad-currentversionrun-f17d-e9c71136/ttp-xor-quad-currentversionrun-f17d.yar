rule TTP_XOR_QUAD_CurrentVersionRun_f17d {
  strings:
    $key_f17d = { a2 12 [2] 86 1c [2] ad 30 [2] 83 12 [2] 97 09 [2] 98 13 [2] 86 0e [2] 84 0f [2] 9f 09 [2] 83 0e [2] 9f 21 }

  condition:
    any of them
}