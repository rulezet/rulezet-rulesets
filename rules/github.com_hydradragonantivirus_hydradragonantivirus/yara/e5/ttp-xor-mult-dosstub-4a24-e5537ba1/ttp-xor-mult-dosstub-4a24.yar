rule TTP_XOR_MULT_DOSStub_4a24 {
  strings:
    $key_4a24 = { 1e 4c [2] 6a 54 [2] 2d 56 [2] 6a 47 [2] 24 4b [2] 28 41 [2] 3f 4a [2] 24 04 [2] 19 }

  condition:
    any of them
}