rule TTP_XOR_MULT_DOSStub_f491 {
  strings:
    $key_f491 = { a0 f9 [2] d4 e1 [2] 93 e3 [2] d4 f2 [2] 9a fe [2] 96 f4 [2] 81 ff [2] 9a b1 [2] a7 }

  condition:
    any of them
}