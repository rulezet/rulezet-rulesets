rule TTP_XOR_MULT_DOSStub_b06f {
  strings:
    $key_b06f = { e4 07 [2] 90 1f [2] d7 1d [2] 90 0c [2] de 00 [2] d2 0a [2] c5 01 [2] de 4f [2] e3 }

  condition:
    any of them
}