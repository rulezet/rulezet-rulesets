rule TTP_XOR_MULT_DOSStub_a8e3 {
  strings:
    $key_a8e3 = { fc 8b [2] 88 93 [2] cf 91 [2] 88 80 [2] c6 8c [2] ca 86 [2] dd 8d [2] c6 c3 [2] fb }

  condition:
    any of them
}