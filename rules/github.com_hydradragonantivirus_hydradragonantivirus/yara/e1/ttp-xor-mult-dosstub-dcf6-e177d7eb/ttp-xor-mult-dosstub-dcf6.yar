rule TTP_XOR_MULT_DOSStub_dcf6 {
  strings:
    $key_dcf6 = { 88 9e [2] fc 86 [2] bb 84 [2] fc 95 [2] b2 99 [2] be 93 [2] a9 98 [2] b2 d6 [2] 8f }

  condition:
    any of them
}