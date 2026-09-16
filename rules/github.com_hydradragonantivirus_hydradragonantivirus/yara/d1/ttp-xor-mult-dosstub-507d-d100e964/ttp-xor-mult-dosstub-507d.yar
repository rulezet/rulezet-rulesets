rule TTP_XOR_MULT_DOSStub_507d {
  strings:
    $key_507d = { 04 15 [2] 70 0d [2] 37 0f [2] 70 1e [2] 3e 12 [2] 32 18 [2] 25 13 [2] 3e 5d [2] 03 }

  condition:
    any of them
}