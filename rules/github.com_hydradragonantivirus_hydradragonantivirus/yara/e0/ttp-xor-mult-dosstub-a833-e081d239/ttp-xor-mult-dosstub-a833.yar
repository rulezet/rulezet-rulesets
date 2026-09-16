rule TTP_XOR_MULT_DOSStub_a833 {
  strings:
    $key_a833 = { fc 5b [2] 88 43 [2] cf 41 [2] 88 50 [2] c6 5c [2] ca 56 [2] dd 5d [2] c6 13 [2] fb }

  condition:
    any of them
}