rule TTP_XOR_MULT_DOSStub_a8f4 {
  strings:
    $key_a8f4 = { fc 9c [2] 88 84 [2] cf 86 [2] 88 97 [2] c6 9b [2] ca 91 [2] dd 9a [2] c6 d4 [2] fb }

  condition:
    any of them
}