rule TTP_XOR_MULT_DOSStub_1011 {
  strings:
    $key_1011 = { 44 79 [2] 30 61 [2] 77 63 [2] 30 72 [2] 7e 7e [2] 72 74 [2] 65 7f [2] 7e 31 [2] 43 }

  condition:
    any of them
}