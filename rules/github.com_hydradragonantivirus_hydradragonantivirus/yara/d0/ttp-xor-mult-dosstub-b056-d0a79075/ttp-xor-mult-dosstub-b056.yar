rule TTP_XOR_MULT_DOSStub_b056 {
  strings:
    $key_b056 = { e4 3e [2] 90 26 [2] d7 24 [2] 90 35 [2] de 39 [2] d2 33 [2] c5 38 [2] de 76 [2] e3 }

  condition:
    any of them
}