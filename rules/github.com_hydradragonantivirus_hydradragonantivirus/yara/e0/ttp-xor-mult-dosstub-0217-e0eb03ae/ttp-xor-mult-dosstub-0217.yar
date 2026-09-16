rule TTP_XOR_MULT_DOSStub_0217 {
  strings:
    $key_0217 = { 56 7f [2] 22 67 [2] 65 65 [2] 22 74 [2] 6c 78 [2] 60 72 [2] 77 79 [2] 6c 37 [2] 51 }

  condition:
    any of them
}