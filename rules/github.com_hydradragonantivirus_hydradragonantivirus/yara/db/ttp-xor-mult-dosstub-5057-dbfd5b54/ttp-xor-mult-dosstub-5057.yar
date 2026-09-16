rule TTP_XOR_MULT_DOSStub_5057 {
  strings:
    $key_5057 = { 04 3f [2] 70 27 [2] 37 25 [2] 70 34 [2] 3e 38 [2] 32 32 [2] 25 39 [2] 3e 77 [2] 03 }

  condition:
    any of them
}