rule TTP_XOR_MULT_DOSStub_2014 {
  strings:
    $key_2014 = { 74 7c [2] 00 64 [2] 47 66 [2] 00 77 [2] 4e 7b [2] 42 71 [2] 55 7a [2] 4e 34 [2] 73 }

  condition:
    any of them
}