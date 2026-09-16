rule TTP_XOR_MULT_DOSStub_bfb9 {
  strings:
    $key_bfb9 = { eb d1 [2] 9f c9 [2] d8 cb [2] 9f da [2] d1 d6 [2] dd dc [2] ca d7 [2] d1 99 [2] ec }

  condition:
    any of them
}