rule TTP_XOR_MULT_DOSStub_0d65 {
  strings:
    $key_0d65 = { 59 0d [2] 2d 15 [2] 6a 17 [2] 2d 06 [2] 63 0a [2] 6f 00 [2] 78 0b [2] 63 45 [2] 5e }

  condition:
    any of them
}