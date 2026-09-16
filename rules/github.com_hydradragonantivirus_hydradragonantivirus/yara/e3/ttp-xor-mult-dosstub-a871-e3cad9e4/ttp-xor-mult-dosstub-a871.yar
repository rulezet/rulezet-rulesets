rule TTP_XOR_MULT_DOSStub_a871 {
  strings:
    $key_a871 = { fc 19 [2] 88 01 [2] cf 03 [2] 88 12 [2] c6 1e [2] ca 14 [2] dd 1f [2] c6 51 [2] fb }

  condition:
    any of them
}