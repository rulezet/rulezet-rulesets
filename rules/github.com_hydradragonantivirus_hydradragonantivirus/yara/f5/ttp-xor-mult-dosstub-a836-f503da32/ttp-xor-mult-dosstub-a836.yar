rule TTP_XOR_MULT_DOSStub_a836 {
  strings:
    $key_a836 = { fc 5e [2] 88 46 [2] cf 44 [2] 88 55 [2] c6 59 [2] ca 53 [2] dd 58 [2] c6 16 [2] fb }

  condition:
    any of them
}