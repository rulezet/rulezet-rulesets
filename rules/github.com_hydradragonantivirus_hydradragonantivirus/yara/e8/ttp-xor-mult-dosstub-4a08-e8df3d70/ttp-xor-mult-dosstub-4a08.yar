rule TTP_XOR_MULT_DOSStub_4a08 {
  strings:
    $key_4a08 = { 1e 60 [2] 6a 78 [2] 2d 7a [2] 6a 6b [2] 24 67 [2] 28 6d [2] 3f 66 [2] 24 28 [2] 19 }

  condition:
    any of them
}