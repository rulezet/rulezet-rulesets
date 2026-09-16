rule TTP_XOR_MULT_DOSStub_a844 {
  strings:
    $key_a844 = { fc 2c [2] 88 34 [2] cf 36 [2] 88 27 [2] c6 2b [2] ca 21 [2] dd 2a [2] c6 64 [2] fb }

  condition:
    any of them
}