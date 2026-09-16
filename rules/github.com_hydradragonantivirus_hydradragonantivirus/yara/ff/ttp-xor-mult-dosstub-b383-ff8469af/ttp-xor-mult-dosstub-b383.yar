rule TTP_XOR_MULT_DOSStub_b383 {
  strings:
    $key_b383 = { e7 eb [2] 93 f3 [2] d4 f1 [2] 93 e0 [2] dd ec [2] d1 e6 [2] c6 ed [2] dd a3 [2] e0 }

  condition:
    any of them
}