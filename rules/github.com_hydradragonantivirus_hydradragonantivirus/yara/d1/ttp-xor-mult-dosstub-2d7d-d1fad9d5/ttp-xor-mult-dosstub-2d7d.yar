rule TTP_XOR_MULT_DOSStub_2d7d {
  strings:
    $key_2d7d = { 79 15 [2] 0d 0d [2] 4a 0f [2] 0d 1e [2] 43 12 [2] 4f 18 [2] 58 13 [2] 43 5d [2] 7e }

  condition:
    any of them
}