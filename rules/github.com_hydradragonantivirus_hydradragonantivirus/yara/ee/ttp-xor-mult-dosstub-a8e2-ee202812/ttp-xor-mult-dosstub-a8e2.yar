rule TTP_XOR_MULT_DOSStub_a8e2 {
  strings:
    $key_a8e2 = { fc 8a [2] 88 92 [2] cf 90 [2] 88 81 [2] c6 8d [2] ca 87 [2] dd 8c [2] c6 c2 [2] fb }

  condition:
    any of them
}