rule TTP_XOR_MULT_DOSStub_1305 {
  strings:
    $key_1305 = { 47 6d [2] 33 75 [2] 74 77 [2] 33 66 [2] 7d 6a [2] 71 60 [2] 66 6b [2] 7d 25 [2] 40 }

  condition:
    any of them
}