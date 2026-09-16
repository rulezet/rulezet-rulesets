rule TTP_XOR_MULT_DOSStub_5d5d {
  strings:
    $key_5d5d = { 09 35 [2] 7d 2d [2] 3a 2f [2] 7d 3e [2] 33 32 [2] 3f 38 [2] 28 33 [2] 33 7d [2] 0e }

  condition:
    any of them
}