rule TTP_XOR_MULT_DOSStub_7408 {
  strings:
    $key_7408 = { 20 60 [2] 54 78 [2] 13 7a [2] 54 6b [2] 1a 67 [2] 16 6d [2] 01 66 [2] 1a 28 [2] 27 }

  condition:
    any of them
}