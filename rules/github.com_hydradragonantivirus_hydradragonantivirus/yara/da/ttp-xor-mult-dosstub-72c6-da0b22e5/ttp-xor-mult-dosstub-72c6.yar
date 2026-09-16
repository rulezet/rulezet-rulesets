rule TTP_XOR_MULT_DOSStub_72c6 {
  strings:
    $key_72c6 = { 26 ae [2] 52 b6 [2] 15 b4 [2] 52 a5 [2] 1c a9 [2] 10 a3 [2] 07 a8 [2] 1c e6 [2] 21 }

  condition:
    any of them
}