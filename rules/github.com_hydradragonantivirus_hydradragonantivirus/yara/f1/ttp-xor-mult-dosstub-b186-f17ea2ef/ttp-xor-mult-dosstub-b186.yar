rule TTP_XOR_MULT_DOSStub_b186 {
  strings:
    $key_b186 = { e5 ee [2] 91 f6 [2] d6 f4 [2] 91 e5 [2] df e9 [2] d3 e3 [2] c4 e8 [2] df a6 [2] e2 }

  condition:
    any of them
}