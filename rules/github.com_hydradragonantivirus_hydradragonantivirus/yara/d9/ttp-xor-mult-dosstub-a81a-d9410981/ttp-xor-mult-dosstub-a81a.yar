rule TTP_XOR_MULT_DOSStub_a81a {
  strings:
    $key_a81a = { fc 72 [2] 88 6a [2] cf 68 [2] 88 79 [2] c6 75 [2] ca 7f [2] dd 74 [2] c6 3a [2] fb }

  condition:
    any of them
}