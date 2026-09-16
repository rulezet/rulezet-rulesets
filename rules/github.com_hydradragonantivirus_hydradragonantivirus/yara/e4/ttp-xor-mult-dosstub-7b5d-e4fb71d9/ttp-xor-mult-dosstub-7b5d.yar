rule TTP_XOR_MULT_DOSStub_7b5d {
  strings:
    $key_7b5d = { 2f 35 [2] 5b 2d [2] 1c 2f [2] 5b 3e [2] 15 32 [2] 19 38 [2] 0e 33 [2] 15 7d [2] 28 }

  condition:
    any of them
}