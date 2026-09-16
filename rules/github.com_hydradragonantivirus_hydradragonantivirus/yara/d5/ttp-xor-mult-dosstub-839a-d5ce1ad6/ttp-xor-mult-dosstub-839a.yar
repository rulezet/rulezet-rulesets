rule TTP_XOR_MULT_DOSStub_839a {
  strings:
    $key_839a = { d7 f2 [2] a3 ea [2] e4 e8 [2] a3 f9 [2] ed f5 [2] e1 ff [2] f6 f4 [2] ed ba [2] d0 }

  condition:
    any of them
}