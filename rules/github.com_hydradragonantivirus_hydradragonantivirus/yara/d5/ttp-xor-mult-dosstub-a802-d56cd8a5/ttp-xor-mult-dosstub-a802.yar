rule TTP_XOR_MULT_DOSStub_a802 {
  strings:
    $key_a802 = { fc 6a [2] 88 72 [2] cf 70 [2] 88 61 [2] c6 6d [2] ca 67 [2] dd 6c [2] c6 22 [2] fb }

  condition:
    any of them
}