rule TTP_XOR_MULT_DOSStub_6305 {
  strings:
    $key_6305 = { 37 6d [2] 43 75 [2] 04 77 [2] 43 66 [2] 0d 6a [2] 01 60 [2] 16 6b [2] 0d 25 [2] 30 }

  condition:
    any of them
}