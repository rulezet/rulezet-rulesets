rule TTP_XOR_MULT_DOSStub_0d47 {
  strings:
    $key_0d47 = { 59 2f [2] 2d 37 [2] 6a 35 [2] 2d 24 [2] 63 28 [2] 6f 22 [2] 78 29 [2] 63 67 [2] 5e }

  condition:
    any of them
}