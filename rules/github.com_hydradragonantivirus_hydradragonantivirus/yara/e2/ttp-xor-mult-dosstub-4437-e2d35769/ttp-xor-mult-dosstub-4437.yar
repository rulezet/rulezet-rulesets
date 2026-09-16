rule TTP_XOR_MULT_DOSStub_4437 {
  strings:
    $key_4437 = { 10 5f [2] 64 47 [2] 23 45 [2] 64 54 [2] 2a 58 [2] 26 52 [2] 31 59 [2] 2a 17 [2] 17 }

  condition:
    any of them
}