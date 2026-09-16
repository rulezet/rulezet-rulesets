rule TTP_XOR_MULT_DOSStub_a815 {
  strings:
    $key_a815 = { fc 7d [2] 88 65 [2] cf 67 [2] 88 76 [2] c6 7a [2] ca 70 [2] dd 7b [2] c6 35 [2] fb }

  condition:
    any of them
}