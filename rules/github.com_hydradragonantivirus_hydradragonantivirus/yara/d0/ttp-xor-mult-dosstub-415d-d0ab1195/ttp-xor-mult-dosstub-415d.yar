rule TTP_XOR_MULT_DOSStub_415d {
  strings:
    $key_415d = { 15 35 [2] 61 2d [2] 26 2f [2] 61 3e [2] 2f 32 [2] 23 38 [2] 34 33 [2] 2f 7d [2] 12 }

  condition:
    any of them
}