rule TTP_XOR_MULT_DOSStub_2015 {
  strings:
    $key_2015 = { 74 7d [2] 00 65 [2] 47 67 [2] 00 76 [2] 4e 7a [2] 42 70 [2] 55 7b [2] 4e 35 [2] 73 }

  condition:
    any of them
}