rule TTP_XOR_MULT_DOSStub_a49a {
  strings:
    $key_a49a = { f0 f2 [2] 84 ea [2] c3 e8 [2] 84 f9 [2] ca f5 [2] c6 ff [2] d1 f4 [2] ca ba [2] f7 }

  condition:
    any of them
}