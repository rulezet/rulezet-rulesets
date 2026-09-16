rule TTP_XOR_MULT_DOSStub_777d {
  strings:
    $key_777d = { 23 15 [2] 57 0d [2] 10 0f [2] 57 1e [2] 19 12 [2] 15 18 [2] 02 13 [2] 19 5d [2] 24 }

  condition:
    any of them
}