rule TTP_XOR_MULT_DOSStub_b08e {
  strings:
    $key_b08e = { e4 e6 [2] 90 fe [2] d7 fc [2] 90 ed [2] de e1 [2] d2 eb [2] c5 e0 [2] de ae [2] e3 }

  condition:
    any of them
}