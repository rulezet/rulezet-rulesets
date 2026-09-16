rule TTP_XOR_MULT_DOSStub_a8f5 {
  strings:
    $key_a8f5 = { fc 9d [2] 88 85 [2] cf 87 [2] 88 96 [2] c6 9a [2] ca 90 [2] dd 9b [2] c6 d5 [2] fb }

  condition:
    any of them
}