rule TTP_XOR_MULT_DOSStub_4d05 {
  strings:
    $key_4d05 = { 19 6d [2] 6d 75 [2] 2a 77 [2] 6d 66 [2] 23 6a [2] 2f 60 [2] 38 6b [2] 23 25 [2] 1e }

  condition:
    any of them
}