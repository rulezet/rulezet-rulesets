rule TTP_XOR_MULT_DOSStub_a805 {
  strings:
    $key_a805 = { fc 6d [2] 88 75 [2] cf 77 [2] 88 66 [2] c6 6a [2] ca 60 [2] dd 6b [2] c6 25 [2] fb }

  condition:
    any of them
}