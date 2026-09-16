rule TTP_XOR_MULT_DOSStub_5138 {
  strings:
    $key_5138 = { 05 50 [2] 71 48 [2] 36 4a [2] 71 5b [2] 3f 57 [2] 33 5d [2] 24 56 [2] 3f 18 [2] 02 }

  condition:
    any of them
}