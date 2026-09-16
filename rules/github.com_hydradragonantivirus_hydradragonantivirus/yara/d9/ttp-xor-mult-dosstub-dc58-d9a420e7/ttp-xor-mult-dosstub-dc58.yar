rule TTP_XOR_MULT_DOSStub_dc58 {
  strings:
    $key_dc58 = { 88 30 [2] fc 28 [2] bb 2a [2] fc 3b [2] b2 37 [2] be 3d [2] a9 36 [2] b2 78 [2] 8f }

  condition:
    any of them
}