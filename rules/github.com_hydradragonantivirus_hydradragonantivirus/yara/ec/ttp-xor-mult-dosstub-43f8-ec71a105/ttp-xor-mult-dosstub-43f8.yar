rule TTP_XOR_MULT_DOSStub_43f8 {
  strings:
    $key_43f8 = { 17 90 [2] 63 88 [2] 24 8a [2] 63 9b [2] 2d 97 [2] 21 9d [2] 36 96 [2] 2d d8 [2] 10 }

  condition:
    any of them
}