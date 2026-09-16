rule TTP_XOR_MULT_DOSStub_43f7 {
  strings:
    $key_43f7 = { 17 9f [2] 63 87 [2] 24 85 [2] 63 94 [2] 2d 98 [2] 21 92 [2] 36 99 [2] 2d d7 [2] 10 }

  condition:
    any of them
}