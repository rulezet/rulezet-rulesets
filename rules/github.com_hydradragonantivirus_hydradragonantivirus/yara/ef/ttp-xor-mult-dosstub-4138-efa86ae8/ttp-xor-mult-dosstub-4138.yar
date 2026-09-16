rule TTP_XOR_MULT_DOSStub_4138 {
  strings:
    $key_4138 = { 15 50 [2] 61 48 [2] 26 4a [2] 61 5b [2] 2f 57 [2] 23 5d [2] 34 56 [2] 2f 18 [2] 12 }

  condition:
    any of them
}