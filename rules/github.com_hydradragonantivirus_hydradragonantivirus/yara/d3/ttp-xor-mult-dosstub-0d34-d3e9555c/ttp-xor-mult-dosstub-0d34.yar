rule TTP_XOR_MULT_DOSStub_0d34 {
  strings:
    $key_0d34 = { 59 5c [2] 2d 44 [2] 6a 46 [2] 2d 57 [2] 63 5b [2] 6f 51 [2] 78 5a [2] 63 14 [2] 5e }

  condition:
    any of them
}