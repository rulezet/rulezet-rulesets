rule TTP_XOR_MULT_DOSStub_a84a {
  strings:
    $key_a84a = { fc 22 [2] 88 3a [2] cf 38 [2] 88 29 [2] c6 25 [2] ca 2f [2] dd 24 [2] c6 6a [2] fb }

  condition:
    any of them
}