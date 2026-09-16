rule TTP_XOR_MULT_DOSStub_f17d {
  strings:
    $key_f17d = { a5 15 [2] d1 0d [2] 96 0f [2] d1 1e [2] 9f 12 [2] 93 18 [2] 84 13 [2] 9f 5d [2] a2 }

  condition:
    any of them
}