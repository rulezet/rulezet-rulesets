rule TTP_XOR_MULT_DOSStub_2a39 {
  strings:
    $key_2a39 = { 7e 51 [2] 0a 49 [2] 4d 4b [2] 0a 5a [2] 44 56 [2] 48 5c [2] 5f 57 [2] 44 19 [2] 79 }

  condition:
    any of them
}