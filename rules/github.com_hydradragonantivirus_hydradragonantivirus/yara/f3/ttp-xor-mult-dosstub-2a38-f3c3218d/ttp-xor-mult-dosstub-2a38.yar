rule TTP_XOR_MULT_DOSStub_2a38 {
  strings:
    $key_2a38 = { 7e 50 [2] 0a 48 [2] 4d 4a [2] 0a 5b [2] 44 57 [2] 48 5d [2] 5f 56 [2] 44 18 [2] 79 }

  condition:
    any of them
}