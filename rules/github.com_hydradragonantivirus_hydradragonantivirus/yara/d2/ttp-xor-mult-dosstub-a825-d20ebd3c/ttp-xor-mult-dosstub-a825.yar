rule TTP_XOR_MULT_DOSStub_a825 {
  strings:
    $key_a825 = { fc 4d [2] 88 55 [2] cf 57 [2] 88 46 [2] c6 4a [2] ca 40 [2] dd 4b [2] c6 05 [2] fb }

  condition:
    any of them
}