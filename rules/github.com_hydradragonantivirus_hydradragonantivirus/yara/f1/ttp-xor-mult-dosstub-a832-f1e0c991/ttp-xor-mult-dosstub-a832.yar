rule TTP_XOR_MULT_DOSStub_a832 {
  strings:
    $key_a832 = { fc 5a [2] 88 42 [2] cf 40 [2] 88 51 [2] c6 5d [2] ca 57 [2] dd 5c [2] c6 12 [2] fb }

  condition:
    any of them
}