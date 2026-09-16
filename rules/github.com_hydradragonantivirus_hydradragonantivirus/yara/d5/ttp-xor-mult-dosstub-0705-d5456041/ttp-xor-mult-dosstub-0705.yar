rule TTP_XOR_MULT_DOSStub_0705 {
  strings:
    $key_0705 = { 53 6d [2] 27 75 [2] 60 77 [2] 27 66 [2] 69 6a [2] 65 60 [2] 72 6b [2] 69 25 [2] 54 }

  condition:
    any of them
}