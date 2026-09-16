rule TTP_XOR_MULT_DOSStub_5174 {
  strings:
    $key_5174 = { 05 1c [2] 71 04 [2] 36 06 [2] 71 17 [2] 3f 1b [2] 33 11 [2] 24 1a [2] 3f 54 [2] 02 }

  condition:
    any of them
}