rule TTP_XOR_MULT_DOSStub_eea8 {
  strings:
    $key_eea8 = { ba c0 [2] ce d8 [2] 89 da [2] ce cb [2] 80 c7 [2] 8c cd [2] 9b c6 [2] 80 88 [2] bd }

  condition:
    any of them
}