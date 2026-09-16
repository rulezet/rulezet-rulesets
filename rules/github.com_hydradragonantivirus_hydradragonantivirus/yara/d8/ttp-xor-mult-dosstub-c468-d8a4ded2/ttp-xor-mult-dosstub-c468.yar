rule TTP_XOR_MULT_DOSStub_c468 {
  strings:
    $key_c468 = { 90 00 [2] e4 18 [2] a3 1a [2] e4 0b [2] aa 07 [2] a6 0d [2] b1 06 [2] aa 48 [2] 97 }

  condition:
    any of them
}