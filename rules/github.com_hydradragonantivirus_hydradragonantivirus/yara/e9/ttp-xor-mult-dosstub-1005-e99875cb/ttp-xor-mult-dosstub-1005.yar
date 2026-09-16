rule TTP_XOR_MULT_DOSStub_1005 {
  strings:
    $key_1005 = { 44 6d [2] 30 75 [2] 77 77 [2] 30 66 [2] 7e 6a [2] 72 60 [2] 65 6b [2] 7e 25 [2] 43 }

  condition:
    any of them
}