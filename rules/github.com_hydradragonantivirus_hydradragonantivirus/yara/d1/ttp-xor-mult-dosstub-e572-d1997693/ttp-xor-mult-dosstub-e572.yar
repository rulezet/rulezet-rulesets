rule TTP_XOR_MULT_DOSStub_e572 {
  strings:
    $key_e572 = { b1 1a [2] c5 02 [2] 82 00 [2] c5 11 [2] 8b 1d [2] 87 17 [2] 90 1c [2] 8b 52 [2] b6 }

  condition:
    any of them
}