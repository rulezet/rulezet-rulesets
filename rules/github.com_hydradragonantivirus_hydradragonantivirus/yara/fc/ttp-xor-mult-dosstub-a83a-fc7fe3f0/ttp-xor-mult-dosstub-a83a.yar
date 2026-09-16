rule TTP_XOR_MULT_DOSStub_a83a {
  strings:
    $key_a83a = { fc 52 [2] 88 4a [2] cf 48 [2] 88 59 [2] c6 55 [2] ca 5f [2] dd 54 [2] c6 1a [2] fb }

  condition:
    any of them
}