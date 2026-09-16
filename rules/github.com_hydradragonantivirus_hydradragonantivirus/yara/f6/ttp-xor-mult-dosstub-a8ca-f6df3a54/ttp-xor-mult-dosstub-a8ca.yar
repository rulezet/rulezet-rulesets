rule TTP_XOR_MULT_DOSStub_a8ca {
  strings:
    $key_a8ca = { fc a2 [2] 88 ba [2] cf b8 [2] 88 a9 [2] c6 a5 [2] ca af [2] dd a4 [2] c6 ea [2] fb }

  condition:
    any of them
}