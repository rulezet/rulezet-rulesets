rule TTP_XOR_MULT_DOSStub_a858 {
  strings:
    $key_a858 = { fc 30 [2] 88 28 [2] cf 2a [2] 88 3b [2] c6 37 [2] ca 3d [2] dd 36 [2] c6 78 [2] fb }

  condition:
    any of them
}