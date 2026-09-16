rule TTP_XOR_MULT_DOSStub_a87f {
  strings:
    $key_a87f = { fc 17 [2] 88 0f [2] cf 0d [2] 88 1c [2] c6 10 [2] ca 1a [2] dd 11 [2] c6 5f [2] fb }

  condition:
    any of them
}