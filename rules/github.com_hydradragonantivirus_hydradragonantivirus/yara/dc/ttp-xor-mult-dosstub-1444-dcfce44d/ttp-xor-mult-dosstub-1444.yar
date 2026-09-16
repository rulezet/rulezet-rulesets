rule TTP_XOR_MULT_DOSStub_1444 {
  strings:
    $key_1444 = { 40 2c [2] 34 34 [2] 73 36 [2] 34 27 [2] 7a 2b [2] 76 21 [2] 61 2a [2] 7a 64 [2] 47 }

  condition:
    any of them
}