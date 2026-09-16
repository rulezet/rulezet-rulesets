rule TTP_XOR_MULT_DOSStub_a840 {
  strings:
    $key_a840 = { fc 28 [2] 88 30 [2] cf 32 [2] 88 23 [2] c6 2f [2] ca 25 [2] dd 2e [2] c6 60 [2] fb }

  condition:
    any of them
}