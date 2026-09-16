rule TTP_XOR_MULT_DOSStub_6065 {
  strings:
    $key_6065 = { 34 0d [2] 40 15 [2] 07 17 [2] 40 06 [2] 0e 0a [2] 02 00 [2] 15 0b [2] 0e 45 [2] 33 }

  condition:
    any of them
}