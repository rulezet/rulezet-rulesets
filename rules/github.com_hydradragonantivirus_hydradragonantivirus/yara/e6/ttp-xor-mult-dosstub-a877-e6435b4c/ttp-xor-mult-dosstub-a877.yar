rule TTP_XOR_MULT_DOSStub_a877 {
  strings:
    $key_a877 = { fc 1f [2] 88 07 [2] cf 05 [2] 88 14 [2] c6 18 [2] ca 12 [2] dd 19 [2] c6 57 [2] fb }

  condition:
    any of them
}