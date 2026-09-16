rule TTP_XOR_MULT_DOSStub_ad82 {
  strings:
    $key_ad82 = { f9 ea [2] 8d f2 [2] ca f0 [2] 8d e1 [2] c3 ed [2] cf e7 [2] d8 ec [2] c3 a2 [2] fe }

  condition:
    any of them
}