rule TTP_XOR_MULT_DOSStub_a83d {
  strings:
    $key_a83d = { fc 55 [2] 88 4d [2] cf 4f [2] 88 5e [2] c6 52 [2] ca 58 [2] dd 53 [2] c6 1d [2] fb }

  condition:
    any of them
}