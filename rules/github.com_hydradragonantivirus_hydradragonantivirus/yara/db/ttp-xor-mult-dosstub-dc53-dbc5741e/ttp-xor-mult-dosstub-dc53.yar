rule TTP_XOR_MULT_DOSStub_dc53 {
  strings:
    $key_dc53 = { 88 3b [2] fc 23 [2] bb 21 [2] fc 30 [2] b2 3c [2] be 36 [2] a9 3d [2] b2 73 [2] 8f }

  condition:
    any of them
}