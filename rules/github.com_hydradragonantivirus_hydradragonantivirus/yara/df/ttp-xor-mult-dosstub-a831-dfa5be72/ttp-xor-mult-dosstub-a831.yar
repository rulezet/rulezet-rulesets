rule TTP_XOR_MULT_DOSStub_a831 {
  strings:
    $key_a831 = { fc 59 [2] 88 41 [2] cf 43 [2] 88 52 [2] c6 5e [2] ca 54 [2] dd 5f [2] c6 11 [2] fb }

  condition:
    any of them
}