rule TTP_XOR_MULT_DOSStub_a827 {
  strings:
    $key_a827 = { fc 4f [2] 88 57 [2] cf 55 [2] 88 44 [2] c6 48 [2] ca 42 [2] dd 49 [2] c6 07 [2] fb }

  condition:
    any of them
}