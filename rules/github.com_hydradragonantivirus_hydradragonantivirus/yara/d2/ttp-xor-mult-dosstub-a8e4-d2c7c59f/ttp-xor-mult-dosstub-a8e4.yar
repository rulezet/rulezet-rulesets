rule TTP_XOR_MULT_DOSStub_a8e4 {
  strings:
    $key_a8e4 = { fc 8c [2] 88 94 [2] cf 96 [2] 88 87 [2] c6 8b [2] ca 81 [2] dd 8a [2] c6 c4 [2] fb }

  condition:
    any of them
}