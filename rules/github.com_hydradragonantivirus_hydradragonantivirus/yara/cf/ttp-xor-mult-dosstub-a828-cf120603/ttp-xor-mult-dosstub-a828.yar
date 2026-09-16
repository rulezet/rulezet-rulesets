rule TTP_XOR_MULT_DOSStub_a828 {
  strings:
    $key_a828 = { fc 40 [2] 88 58 [2] cf 5a [2] 88 4b [2] c6 47 [2] ca 4d [2] dd 46 [2] c6 08 [2] fb }

  condition:
    any of them
}