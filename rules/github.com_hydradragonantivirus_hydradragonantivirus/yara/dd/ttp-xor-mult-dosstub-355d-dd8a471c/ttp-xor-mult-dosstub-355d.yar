rule TTP_XOR_MULT_DOSStub_355d {
  strings:
    $key_355d = { 61 35 [2] 15 2d [2] 52 2f [2] 15 3e [2] 5b 32 [2] 57 38 [2] 40 33 [2] 5b 7d [2] 66 }

  condition:
    any of them
}