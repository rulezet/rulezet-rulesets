rule TTP_XOR_MULT_DOSStub_414c {
  strings:
    $key_414c = { 15 24 [2] 61 3c [2] 26 3e [2] 61 2f [2] 2f 23 [2] 23 29 [2] 34 22 [2] 2f 6c [2] 12 }

  condition:
    any of them
}