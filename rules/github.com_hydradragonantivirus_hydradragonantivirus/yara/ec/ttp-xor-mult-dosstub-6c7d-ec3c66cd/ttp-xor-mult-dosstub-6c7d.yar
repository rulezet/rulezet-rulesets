rule TTP_XOR_MULT_DOSStub_6c7d {
  strings:
    $key_6c7d = { 38 15 [2] 4c 0d [2] 0b 0f [2] 4c 1e [2] 02 12 [2] 0e 18 [2] 19 13 [2] 02 5d [2] 3f }

  condition:
    any of them
}