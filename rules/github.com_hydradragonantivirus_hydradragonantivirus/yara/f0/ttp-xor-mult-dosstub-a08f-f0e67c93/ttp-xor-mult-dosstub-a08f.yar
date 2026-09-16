rule TTP_XOR_MULT_DOSStub_a08f {
  strings:
    $key_a08f = { f4 e7 [2] 80 ff [2] c7 fd [2] 80 ec [2] ce e0 [2] c2 ea [2] d5 e1 [2] ce af [2] f3 }

  condition:
    any of them
}