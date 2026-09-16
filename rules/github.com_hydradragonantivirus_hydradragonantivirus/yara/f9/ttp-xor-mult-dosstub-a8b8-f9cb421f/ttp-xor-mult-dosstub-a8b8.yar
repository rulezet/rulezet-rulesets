rule TTP_XOR_MULT_DOSStub_a8b8 {
  strings:
    $key_a8b8 = { fc d0 [2] 88 c8 [2] cf ca [2] 88 db [2] c6 d7 [2] ca dd [2] dd d6 [2] c6 98 [2] fb }

  condition:
    any of them
}