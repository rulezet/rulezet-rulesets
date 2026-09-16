rule TTP_XOR_MULT_DOSStub_5105 {
  strings:
    $key_5105 = { 05 6d [2] 71 75 [2] 36 77 [2] 71 66 [2] 3f 6a [2] 33 60 [2] 24 6b [2] 3f 25 [2] 02 }

  condition:
    any of them
}