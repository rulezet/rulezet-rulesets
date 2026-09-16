rule TTP_XOR_MULT_DOSStub_ddb7 {
  strings:
    $key_ddb7 = { 89 df [2] fd c7 [2] ba c5 [2] fd d4 [2] b3 d8 [2] bf d2 [2] a8 d9 [2] b3 97 [2] 8e }

  condition:
    any of them
}