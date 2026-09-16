rule TTP_XOR_MULT_DOSStub_a86d {
  strings:
    $key_a86d = { fc 05 [2] 88 1d [2] cf 1f [2] 88 0e [2] c6 02 [2] ca 08 [2] dd 03 [2] c6 4d [2] fb }

  condition:
    any of them
}