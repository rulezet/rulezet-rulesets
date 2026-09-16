rule TTP_XOR_MULT_DOSStub_dc8f {
  strings:
    $key_dc8f = { 88 e7 [2] fc ff [2] bb fd [2] fc ec [2] b2 e0 [2] be ea [2] a9 e1 [2] b2 af [2] 8f }

  condition:
    any of them
}