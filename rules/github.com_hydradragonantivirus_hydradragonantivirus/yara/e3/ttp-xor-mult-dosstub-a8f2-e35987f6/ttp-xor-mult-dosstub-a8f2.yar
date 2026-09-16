rule TTP_XOR_MULT_DOSStub_a8f2 {
  strings:
    $key_a8f2 = { fc 9a [2] 88 82 [2] cf 80 [2] 88 91 [2] c6 9d [2] ca 97 [2] dd 9c [2] c6 d2 [2] fb }

  condition:
    any of them
}