rule TTP_XOR_MULT_DOSStub_ac82 {
  strings:
    $key_ac82 = { f8 ea [2] 8c f2 [2] cb f0 [2] 8c e1 [2] c2 ed [2] ce e7 [2] d9 ec [2] c2 a2 [2] ff }

  condition:
    any of them
}