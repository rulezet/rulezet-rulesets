rule TTP_XOR_MULT_DOSStub_dc8e {
  strings:
    $key_dc8e = { 88 e6 [2] fc fe [2] bb fc [2] fc ed [2] b2 e1 [2] be eb [2] a9 e0 [2] b2 ae [2] 8f }

  condition:
    any of them
}