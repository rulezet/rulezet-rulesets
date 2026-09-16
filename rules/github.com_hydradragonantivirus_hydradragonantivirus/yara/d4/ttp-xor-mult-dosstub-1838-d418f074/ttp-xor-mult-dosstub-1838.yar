rule TTP_XOR_MULT_DOSStub_1838 {
  strings:
    $key_1838 = { 4c 50 [2] 38 48 [2] 7f 4a [2] 38 5b [2] 76 57 [2] 7a 5d [2] 6d 56 [2] 76 18 [2] 4b }

  condition:
    any of them
}