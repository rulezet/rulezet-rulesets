rule TTP_XOR_MULT_DOSStub_cadc {
  strings:
    $key_cadc = { 9e b4 [2] ea ac [2] ad ae [2] ea bf [2] a4 b3 [2] a8 b9 [2] bf b2 [2] a4 fc [2] 99 }

  condition:
    any of them
}