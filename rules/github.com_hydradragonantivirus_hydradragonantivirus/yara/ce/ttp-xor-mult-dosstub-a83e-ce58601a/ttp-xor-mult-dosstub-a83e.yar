rule TTP_XOR_MULT_DOSStub_a83e {
  strings:
    $key_a83e = { fc 56 [2] 88 4e [2] cf 4c [2] 88 5d [2] c6 51 [2] ca 5b [2] dd 50 [2] c6 1e [2] fb }

  condition:
    any of them
}