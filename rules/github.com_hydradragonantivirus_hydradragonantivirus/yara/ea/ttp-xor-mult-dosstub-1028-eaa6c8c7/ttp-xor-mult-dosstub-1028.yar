rule TTP_XOR_MULT_DOSStub_1028 {
  strings:
    $key_1028 = { 44 40 [2] 30 58 [2] 77 5a [2] 30 4b [2] 7e 47 [2] 72 4d [2] 65 46 [2] 7e 08 [2] 43 }

  condition:
    any of them
}