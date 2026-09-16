rule TTP_XOR_MULT_DOSStub_ddb3 {
  strings:
    $key_ddb3 = { 89 db [2] fd c3 [2] ba c1 [2] fd d0 [2] b3 dc [2] bf d6 [2] a8 dd [2] b3 93 [2] 8e }

  condition:
    any of them
}