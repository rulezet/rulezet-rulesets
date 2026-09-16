rule TTP_XOR_MULT_DOSStub_7708 {
  strings:
    $key_7708 = { 23 60 [2] 57 78 [2] 10 7a [2] 57 6b [2] 19 67 [2] 15 6d [2] 02 66 [2] 19 28 [2] 24 }

  condition:
    any of them
}