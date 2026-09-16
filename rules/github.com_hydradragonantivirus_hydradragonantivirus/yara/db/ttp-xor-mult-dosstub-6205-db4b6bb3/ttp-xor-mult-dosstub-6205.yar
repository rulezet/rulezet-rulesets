rule TTP_XOR_MULT_DOSStub_6205 {
  strings:
    $key_6205 = { 36 6d [2] 42 75 [2] 05 77 [2] 42 66 [2] 0c 6a [2] 00 60 [2] 17 6b [2] 0c 25 [2] 31 }

  condition:
    any of them
}