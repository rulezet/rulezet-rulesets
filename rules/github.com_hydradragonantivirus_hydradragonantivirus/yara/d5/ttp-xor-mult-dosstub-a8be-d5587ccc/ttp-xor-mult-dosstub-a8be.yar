rule TTP_XOR_MULT_DOSStub_a8be {
  strings:
    $key_a8be = { fc d6 [2] 88 ce [2] cf cc [2] 88 dd [2] c6 d1 [2] ca db [2] dd d0 [2] c6 9e [2] fb }

  condition:
    any of them
}