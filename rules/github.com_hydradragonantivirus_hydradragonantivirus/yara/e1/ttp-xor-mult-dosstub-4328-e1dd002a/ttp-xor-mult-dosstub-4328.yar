rule TTP_XOR_MULT_DOSStub_4328 {
  strings:
    $key_4328 = { 17 40 [2] 63 58 [2] 24 5a [2] 63 4b [2] 2d 47 [2] 21 4d [2] 36 46 [2] 2d 08 [2] 10 }

  condition:
    any of them
}