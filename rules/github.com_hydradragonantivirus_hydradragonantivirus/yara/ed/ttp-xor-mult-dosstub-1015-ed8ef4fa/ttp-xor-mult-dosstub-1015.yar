rule TTP_XOR_MULT_DOSStub_1015 {
  strings:
    $key_1015 = { 44 7d [2] 30 65 [2] 77 67 [2] 30 76 [2] 7e 7a [2] 72 70 [2] 65 7b [2] 7e 35 [2] 43 }

  condition:
    any of them
}