rule TTP_XOR_MULT_DOSStub_a814 {
  strings:
    $key_a814 = { fc 7c [2] 88 64 [2] cf 66 [2] 88 77 [2] c6 7b [2] ca 71 [2] dd 7a [2] c6 34 [2] fb }

  condition:
    any of them
}