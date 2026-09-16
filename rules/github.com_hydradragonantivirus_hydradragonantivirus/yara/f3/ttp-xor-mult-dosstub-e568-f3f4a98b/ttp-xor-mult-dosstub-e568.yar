rule TTP_XOR_MULT_DOSStub_e568 {
  strings:
    $key_e568 = { b1 00 [2] c5 18 [2] 82 1a [2] c5 0b [2] 8b 07 [2] 87 0d [2] 90 06 [2] 8b 48 [2] b6 }

  condition:
    any of them
}