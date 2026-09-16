rule TTP_XOR_MULT_DOSStub_dc9a {
  strings:
    $key_dc9a = { 88 f2 [2] fc ea [2] bb e8 [2] fc f9 [2] b2 f5 [2] be ff [2] a9 f4 [2] b2 ba [2] 8f }

  condition:
    any of them
}