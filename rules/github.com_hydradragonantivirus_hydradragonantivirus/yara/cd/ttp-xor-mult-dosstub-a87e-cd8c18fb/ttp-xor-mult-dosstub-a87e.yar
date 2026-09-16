rule TTP_XOR_MULT_DOSStub_a87e {
  strings:
    $key_a87e = { fc 16 [2] 88 0e [2] cf 0c [2] 88 1d [2] c6 11 [2] ca 1b [2] dd 10 [2] c6 5e [2] fb }

  condition:
    any of them
}