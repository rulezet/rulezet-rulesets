rule TTP_XOR_MULT_DOSStub_a8b5 {
  strings:
    $key_a8b5 = { fc dd [2] 88 c5 [2] cf c7 [2] 88 d6 [2] c6 da [2] ca d0 [2] dd db [2] c6 95 [2] fb }

  condition:
    any of them
}