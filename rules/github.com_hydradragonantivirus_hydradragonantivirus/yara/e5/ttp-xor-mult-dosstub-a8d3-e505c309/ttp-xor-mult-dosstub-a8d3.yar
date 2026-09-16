rule TTP_XOR_MULT_DOSStub_a8d3 {
  strings:
    $key_a8d3 = { fc bb [2] 88 a3 [2] cf a1 [2] 88 b0 [2] c6 bc [2] ca b6 [2] dd bd [2] c6 f3 [2] fb }

  condition:
    any of them
}