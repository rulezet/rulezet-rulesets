rule TTP_XOR_MULT_DOSStub_dc63 {
  strings:
    $key_dc63 = { 88 0b [2] fc 13 [2] bb 11 [2] fc 00 [2] b2 0c [2] be 06 [2] a9 0d [2] b2 43 [2] 8f }

  condition:
    any of them
}