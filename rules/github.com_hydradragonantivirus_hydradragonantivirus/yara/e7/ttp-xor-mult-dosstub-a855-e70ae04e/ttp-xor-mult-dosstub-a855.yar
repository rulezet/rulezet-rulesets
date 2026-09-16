rule TTP_XOR_MULT_DOSStub_a855 {
  strings:
    $key_a855 = { fc 3d [2] 88 25 [2] cf 27 [2] 88 36 [2] c6 3a [2] ca 30 [2] dd 3b [2] c6 75 [2] fb }

  condition:
    any of them
}