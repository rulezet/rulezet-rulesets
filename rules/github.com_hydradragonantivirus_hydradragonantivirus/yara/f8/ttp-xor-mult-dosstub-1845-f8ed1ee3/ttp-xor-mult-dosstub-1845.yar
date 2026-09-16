rule TTP_XOR_MULT_DOSStub_1845 {
  strings:
    $key_1845 = { 4c 2d [2] 38 35 [2] 7f 37 [2] 38 26 [2] 76 2a [2] 7a 20 [2] 6d 2b [2] 76 65 [2] 4b }

  condition:
    any of them
}