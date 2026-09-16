rule TTP_XOR_MULT_DOSStub_a821 {
  strings:
    $key_a821 = { fc 49 [2] 88 51 [2] cf 53 [2] 88 42 [2] c6 4e [2] ca 44 [2] dd 4f [2] c6 01 [2] fb }

  condition:
    any of them
}