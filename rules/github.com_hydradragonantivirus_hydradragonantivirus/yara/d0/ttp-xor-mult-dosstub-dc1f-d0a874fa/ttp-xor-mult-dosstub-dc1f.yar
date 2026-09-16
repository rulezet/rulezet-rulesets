rule TTP_XOR_MULT_DOSStub_dc1f {
  strings:
    $key_dc1f = { 88 77 [2] fc 6f [2] bb 6d [2] fc 7c [2] b2 70 [2] be 7a [2] a9 71 [2] b2 3f [2] 8f }

  condition:
    any of them
}