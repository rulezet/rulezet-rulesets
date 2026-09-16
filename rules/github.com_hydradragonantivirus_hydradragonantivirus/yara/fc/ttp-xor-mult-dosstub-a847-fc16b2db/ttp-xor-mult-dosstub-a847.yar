rule TTP_XOR_MULT_DOSStub_a847 {
  strings:
    $key_a847 = { fc 2f [2] 88 37 [2] cf 35 [2] 88 24 [2] c6 28 [2] ca 22 [2] dd 29 [2] c6 67 [2] fb }

  condition:
    any of them
}