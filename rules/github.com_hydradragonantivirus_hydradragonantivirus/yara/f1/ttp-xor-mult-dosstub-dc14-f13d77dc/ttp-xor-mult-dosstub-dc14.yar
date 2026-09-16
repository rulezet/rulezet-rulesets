rule TTP_XOR_MULT_DOSStub_dc14 {
  strings:
    $key_dc14 = { 88 7c [2] fc 64 [2] bb 66 [2] fc 77 [2] b2 7b [2] be 71 [2] a9 7a [2] b2 34 [2] 8f }

  condition:
    any of them
}