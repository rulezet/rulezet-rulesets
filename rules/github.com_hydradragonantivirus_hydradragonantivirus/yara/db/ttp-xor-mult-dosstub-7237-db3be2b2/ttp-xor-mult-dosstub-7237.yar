rule TTP_XOR_MULT_DOSStub_7237 {
  strings:
    $key_7237 = { 26 5f [2] 52 47 [2] 15 45 [2] 52 54 [2] 1c 58 [2] 10 52 [2] 07 59 [2] 1c 17 [2] 21 }

  condition:
    any of them
}