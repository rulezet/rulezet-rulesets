rule TTP_XOR_MULT_DOSStub_0d04 {
  strings:
    $key_0d04 = { 59 6c [2] 2d 74 [2] 6a 76 [2] 2d 67 [2] 63 6b [2] 6f 61 [2] 78 6a [2] 63 24 [2] 5e }

  condition:
    any of them
}