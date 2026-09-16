rule TTP_XOR_MULT_DOSStub_a83f {
  strings:
    $key_a83f = { fc 57 [2] 88 4f [2] cf 4d [2] 88 5c [2] c6 50 [2] ca 5a [2] dd 51 [2] c6 1f [2] fb }

  condition:
    any of them
}