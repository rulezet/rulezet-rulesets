rule TTP_XOR_MULT_DOSStub_a191 {
  strings:
    $key_a191 = { f5 f9 [2] 81 e1 [2] c6 e3 [2] 81 f2 [2] cf fe [2] c3 f4 [2] d4 ff [2] cf b1 [2] f2 }

  condition:
    any of them
}