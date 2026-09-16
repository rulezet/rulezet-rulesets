rule TTP_XOR_MULT_DOSStub_3918 {
  strings:
    $key_3918 = { 6d 70 [2] 19 68 [2] 5e 6a [2] 19 7b [2] 57 77 [2] 5b 7d [2] 4c 76 [2] 57 38 [2] 6a }

  condition:
    any of them
}