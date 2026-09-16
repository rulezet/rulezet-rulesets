rule TTP_XOR_MULT_DOSStub_a879 {
  strings:
    $key_a879 = { fc 11 [2] 88 09 [2] cf 0b [2] 88 1a [2] c6 16 [2] ca 1c [2] dd 17 [2] c6 59 [2] fb }

  condition:
    any of them
}