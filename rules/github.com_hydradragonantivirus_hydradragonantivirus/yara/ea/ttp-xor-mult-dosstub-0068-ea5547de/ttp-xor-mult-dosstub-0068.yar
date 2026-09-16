rule TTP_XOR_MULT_DOSStub_0068 {
  strings:
    $key_0068 = { 54 00 [2] 20 18 [2] 67 1a [2] 20 0b [2] 6e 07 [2] 62 0d [2] 75 06 [2] 6e 48 [2] 53 }

  condition:
    any of them
}