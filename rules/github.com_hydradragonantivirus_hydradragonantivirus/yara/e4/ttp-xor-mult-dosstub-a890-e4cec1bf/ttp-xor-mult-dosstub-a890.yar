rule TTP_XOR_MULT_DOSStub_a890 {
  strings:
    $key_a890 = { fc f8 [2] 88 e0 [2] cf e2 [2] 88 f3 [2] c6 ff [2] ca f5 [2] dd fe [2] c6 b0 [2] fb }

  condition:
    any of them
}