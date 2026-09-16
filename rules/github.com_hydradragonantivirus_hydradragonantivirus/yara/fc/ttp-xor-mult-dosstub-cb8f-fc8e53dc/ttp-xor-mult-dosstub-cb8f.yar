rule TTP_XOR_MULT_DOSStub_cb8f {
  strings:
    $key_cb8f = { 9f e7 [2] eb ff [2] ac fd [2] eb ec [2] a5 e0 [2] a9 ea [2] be e1 [2] a5 af [2] 98 }

  condition:
    any of them
}