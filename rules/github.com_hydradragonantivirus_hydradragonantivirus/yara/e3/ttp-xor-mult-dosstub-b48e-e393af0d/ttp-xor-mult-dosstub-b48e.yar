rule TTP_XOR_MULT_DOSStub_b48e {
  strings:
    $key_b48e = { e0 e6 [2] 94 fe [2] d3 fc [2] 94 ed [2] da e1 [2] d6 eb [2] c1 e0 [2] da ae [2] e7 }

  condition:
    any of them
}