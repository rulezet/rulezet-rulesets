rule TTP_XOR_MULT_DOSStub_0615 {
  strings:
    $key_0615 = { 52 7d [2] 26 65 [2] 61 67 [2] 26 76 [2] 68 7a [2] 64 70 [2] 73 7b [2] 68 35 [2] 55 }

  condition:
    any of them
}