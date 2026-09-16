rule TTP_XOR_MULT_DOSStub_5a05 {
  strings:
    $key_5a05 = { 0e 6d [2] 7a 75 [2] 3d 77 [2] 7a 66 [2] 34 6a [2] 38 60 [2] 2f 6b [2] 34 25 [2] 09 }

  condition:
    any of them
}