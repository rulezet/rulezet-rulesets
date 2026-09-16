rule TTP_XOR_MULT_DOSStub_a86f {
  strings:
    $key_a86f = { fc 07 [2] 88 1f [2] cf 1d [2] 88 0c [2] c6 00 [2] ca 0a [2] dd 01 [2] c6 4f [2] fb }

  condition:
    any of them
}