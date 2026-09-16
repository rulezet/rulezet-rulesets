rule TTP_XOR_MULT_DOSStub_2018 {
  strings:
    $key_2018 = { 74 70 [2] 00 68 [2] 47 6a [2] 00 7b [2] 4e 77 [2] 42 7d [2] 55 76 [2] 4e 38 [2] 73 }

  condition:
    any of them
}