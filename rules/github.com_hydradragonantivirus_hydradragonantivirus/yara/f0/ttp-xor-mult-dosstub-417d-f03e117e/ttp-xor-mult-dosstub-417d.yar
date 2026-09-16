rule TTP_XOR_MULT_DOSStub_417d {
  strings:
    $key_417d = { 15 15 [2] 61 0d [2] 26 0f [2] 61 1e [2] 2f 12 [2] 23 18 [2] 34 13 [2] 2f 5d [2] 12 }

  condition:
    any of them
}