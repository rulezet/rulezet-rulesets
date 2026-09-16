rule TTP_XOR_MULT_DOSStub_a82c {
  strings:
    $key_a82c = { fc 44 [2] 88 5c [2] cf 5e [2] 88 4f [2] c6 43 [2] ca 49 [2] dd 42 [2] c6 0c [2] fb }

  condition:
    any of them
}