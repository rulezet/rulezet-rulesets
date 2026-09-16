rule TTP_XOR_MULT_DOSStub_7502 {
  strings:
    $key_7502 = { 21 6a [2] 55 72 [2] 12 70 [2] 55 61 [2] 1b 6d [2] 17 67 [2] 00 6c [2] 1b 22 [2] 26 }

  condition:
    any of them
}