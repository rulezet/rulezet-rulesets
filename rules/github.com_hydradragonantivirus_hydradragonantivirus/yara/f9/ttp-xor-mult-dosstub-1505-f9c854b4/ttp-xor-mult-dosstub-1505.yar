rule TTP_XOR_MULT_DOSStub_1505 {
  strings:
    $key_1505 = { 41 6d [2] 35 75 [2] 72 77 [2] 35 66 [2] 7b 6a [2] 77 60 [2] 60 6b [2] 7b 25 [2] 46 }

  condition:
    any of them
}