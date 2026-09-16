rule TTP_XOR_MULT_DOSStub_5a24 {
  strings:
    $key_5a24 = { 0e 4c [2] 7a 54 [2] 3d 56 [2] 7a 47 [2] 34 4b [2] 38 41 [2] 2f 4a [2] 34 04 [2] 09 }

  condition:
    any of them
}