rule TTP_XOR_MULT_DOSStub_43e8 {
  strings:
    $key_43e8 = { 17 80 [2] 63 98 [2] 24 9a [2] 63 8b [2] 2d 87 [2] 21 8d [2] 36 86 [2] 2d c8 [2] 10 }

  condition:
    any of them
}