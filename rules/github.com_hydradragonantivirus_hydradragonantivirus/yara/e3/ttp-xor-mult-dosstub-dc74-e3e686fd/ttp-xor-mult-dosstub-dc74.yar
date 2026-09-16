rule TTP_XOR_MULT_DOSStub_dc74 {
  strings:
    $key_dc74 = { 88 1c [2] fc 04 [2] bb 06 [2] fc 17 [2] b2 1b [2] be 11 [2] a9 1a [2] b2 54 [2] 8f }

  condition:
    any of them
}