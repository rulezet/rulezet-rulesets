rule TTP_XOR_MULT_DOSStub_dc88 {
  strings:
    $key_dc88 = { 88 e0 [2] fc f8 [2] bb fa [2] fc eb [2] b2 e7 [2] be ed [2] a9 e6 [2] b2 a8 [2] 8f }

  condition:
    any of them
}