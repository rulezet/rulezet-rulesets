rule TTP_XOR_MULT_DOSStub_7a22 {
  strings:
    $key_7a22 = { 2e 4a [2] 5a 52 [2] 1d 50 [2] 5a 41 [2] 14 4d [2] 18 47 [2] 0f 4c [2] 14 02 [2] 29 }

  condition:
    any of them
}