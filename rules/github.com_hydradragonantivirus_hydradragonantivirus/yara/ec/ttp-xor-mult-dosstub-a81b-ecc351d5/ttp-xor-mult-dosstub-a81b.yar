rule TTP_XOR_MULT_DOSStub_a81b {
  strings:
    $key_a81b = { fc 73 [2] 88 6b [2] cf 69 [2] 88 78 [2] c6 74 [2] ca 7e [2] dd 75 [2] c6 3b [2] fb }

  condition:
    any of them
}