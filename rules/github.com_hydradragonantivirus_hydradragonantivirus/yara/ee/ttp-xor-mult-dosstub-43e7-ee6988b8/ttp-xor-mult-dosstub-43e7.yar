rule TTP_XOR_MULT_DOSStub_43e7 {
  strings:
    $key_43e7 = { 17 8f [2] 63 97 [2] 24 95 [2] 63 84 [2] 2d 88 [2] 21 82 [2] 36 89 [2] 2d c7 [2] 10 }

  condition:
    any of them
}