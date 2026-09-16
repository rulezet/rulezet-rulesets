rule TTP_XOR_MULT_DOSStub_a8fa {
  strings:
    $key_a8fa = { fc 92 [2] 88 8a [2] cf 88 [2] 88 99 [2] c6 95 [2] ca 9f [2] dd 94 [2] c6 da [2] fb }

  condition:
    any of them
}