rule TTP_XOR_MULT_DOSStub_2038 {
  strings:
    $key_2038 = { 74 50 [2] 00 48 [2] 47 4a [2] 00 5b [2] 4e 57 [2] 42 5d [2] 55 56 [2] 4e 18 [2] 73 }

  condition:
    any of them
}