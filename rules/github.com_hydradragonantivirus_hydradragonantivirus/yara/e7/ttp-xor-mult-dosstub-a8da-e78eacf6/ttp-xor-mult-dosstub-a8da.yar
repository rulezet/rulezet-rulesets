rule TTP_XOR_MULT_DOSStub_a8da {
  strings:
    $key_a8da = { fc b2 [2] 88 aa [2] cf a8 [2] 88 b9 [2] c6 b5 [2] ca bf [2] dd b4 [2] c6 fa [2] fb }

  condition:
    any of them
}