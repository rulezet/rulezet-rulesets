rule TTP_XOR_MULT_DOSStub_a8cb {
  strings:
    $key_a8cb = { fc a3 [2] 88 bb [2] cf b9 [2] 88 a8 [2] c6 a4 [2] ca ae [2] dd a5 [2] c6 eb [2] fb }

  condition:
    any of them
}