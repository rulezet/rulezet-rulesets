rule TTP_XOR_MULT_DOSStub_0430 {
  strings:
    $key_0430 = { 50 58 [2] 24 40 [2] 63 42 [2] 24 53 [2] 6a 5f [2] 66 55 [2] 71 5e [2] 6a 10 [2] 57 }

  condition:
    any of them
}