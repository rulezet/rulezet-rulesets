rule TTP_XOR_MULT_DOSStub_b291 {
  strings:
    $key_b291 = { e6 f9 [2] 92 e1 [2] d5 e3 [2] 92 f2 [2] dc fe [2] d0 f4 [2] c7 ff [2] dc b1 [2] e1 }

  condition:
    any of them
}