rule TTP_XOR_MULT_DOSStub_a093 {
  strings:
    $key_a093 = { f4 fb [2] 80 e3 [2] c7 e1 [2] 80 f0 [2] ce fc [2] c2 f6 [2] d5 fd [2] ce b3 [2] f3 }

  condition:
    any of them
}