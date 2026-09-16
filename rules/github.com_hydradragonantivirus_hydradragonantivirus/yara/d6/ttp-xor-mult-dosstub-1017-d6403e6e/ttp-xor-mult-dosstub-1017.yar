rule TTP_XOR_MULT_DOSStub_1017 {
  strings:
    $key_1017 = { 44 7f [2] 30 67 [2] 77 65 [2] 30 74 [2] 7e 78 [2] 72 72 [2] 65 79 [2] 7e 37 [2] 43 }

  condition:
    any of them
}