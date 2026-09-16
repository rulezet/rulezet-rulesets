rule TTP_XOR_MULT_DOSStub_5a08 {
  strings:
    $key_5a08 = { 0e 60 [2] 7a 78 [2] 3d 7a [2] 7a 6b [2] 34 67 [2] 38 6d [2] 2f 66 [2] 34 28 [2] 09 }

  condition:
    any of them
}