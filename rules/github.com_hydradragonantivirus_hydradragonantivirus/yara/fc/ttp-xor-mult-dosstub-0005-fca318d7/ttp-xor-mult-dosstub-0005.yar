rule TTP_XOR_MULT_DOSStub_0005 {
  strings:
    $key_0005 = { 54 6d [2] 20 75 [2] 67 77 [2] 20 66 [2] 6e 6a [2] 62 60 [2] 75 6b [2] 6e 25 [2] 53 }

  condition:
    any of them
}