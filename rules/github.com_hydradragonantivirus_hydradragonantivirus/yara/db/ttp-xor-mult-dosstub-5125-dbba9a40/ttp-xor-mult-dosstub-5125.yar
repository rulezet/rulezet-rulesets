rule TTP_XOR_MULT_DOSStub_5125 {
  strings:
    $key_5125 = { 05 4d [2] 71 55 [2] 36 57 [2] 71 46 [2] 3f 4a [2] 33 40 [2] 24 4b [2] 3f 05 [2] 02 }

  condition:
    any of them
}