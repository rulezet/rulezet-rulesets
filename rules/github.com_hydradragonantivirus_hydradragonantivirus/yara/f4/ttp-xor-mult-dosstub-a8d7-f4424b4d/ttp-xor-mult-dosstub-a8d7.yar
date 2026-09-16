rule TTP_XOR_MULT_DOSStub_a8d7 {
  strings:
    $key_a8d7 = { fc bf [2] 88 a7 [2] cf a5 [2] 88 b4 [2] c6 b8 [2] ca b2 [2] dd b9 [2] c6 f7 [2] fb }

  condition:
    any of them
}