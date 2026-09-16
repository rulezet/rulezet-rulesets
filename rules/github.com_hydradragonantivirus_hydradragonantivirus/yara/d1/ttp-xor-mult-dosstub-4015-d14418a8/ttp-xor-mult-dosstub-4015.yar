rule TTP_XOR_MULT_DOSStub_4015 {
  strings:
    $key_4015 = { 14 7d [2] 60 65 [2] 27 67 [2] 60 76 [2] 2e 7a [2] 22 70 [2] 35 7b [2] 2e 35 [2] 13 }

  condition:
    any of them
}