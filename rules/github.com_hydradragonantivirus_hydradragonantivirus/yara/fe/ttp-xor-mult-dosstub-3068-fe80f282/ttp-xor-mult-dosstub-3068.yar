rule TTP_XOR_MULT_DOSStub_3068 {
  strings:
    $key_3068 = { 64 00 [2] 10 18 [2] 57 1a [2] 10 0b [2] 5e 07 [2] 52 0d [2] 45 06 [2] 5e 48 [2] 63 }

  condition:
    any of them
}