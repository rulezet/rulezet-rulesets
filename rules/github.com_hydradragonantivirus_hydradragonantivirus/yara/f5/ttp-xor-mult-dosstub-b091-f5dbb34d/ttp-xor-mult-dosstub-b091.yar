rule TTP_XOR_MULT_DOSStub_b091 {
  strings:
    $key_b091 = { e4 f9 [2] 90 e1 [2] d7 e3 [2] 90 f2 [2] de fe [2] d2 f4 [2] c5 ff [2] de b1 [2] e3 }

  condition:
    any of them
}