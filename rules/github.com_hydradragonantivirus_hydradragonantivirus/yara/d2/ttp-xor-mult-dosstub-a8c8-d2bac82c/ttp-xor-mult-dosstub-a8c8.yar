rule TTP_XOR_MULT_DOSStub_a8c8 {
  strings:
    $key_a8c8 = { fc a0 [2] 88 b8 [2] cf ba [2] 88 ab [2] c6 a7 [2] ca ad [2] dd a6 [2] c6 e8 [2] fb }

  condition:
    any of them
}