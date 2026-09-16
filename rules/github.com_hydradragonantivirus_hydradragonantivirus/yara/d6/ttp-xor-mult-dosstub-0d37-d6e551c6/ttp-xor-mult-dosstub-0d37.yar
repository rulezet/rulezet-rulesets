rule TTP_XOR_MULT_DOSStub_0d37 {
  strings:
    $key_0d37 = { 59 5f [2] 2d 47 [2] 6a 45 [2] 2d 54 [2] 63 58 [2] 6f 52 [2] 78 59 [2] 63 17 [2] 5e }

  condition:
    any of them
}