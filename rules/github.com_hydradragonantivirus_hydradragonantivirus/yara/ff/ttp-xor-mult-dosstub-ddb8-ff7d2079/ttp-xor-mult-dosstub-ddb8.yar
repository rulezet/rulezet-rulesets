rule TTP_XOR_MULT_DOSStub_ddb8 {
  strings:
    $key_ddb8 = { 89 d0 [2] fd c8 [2] ba ca [2] fd db [2] b3 d7 [2] bf dd [2] a8 d6 [2] b3 98 [2] 8e }

  condition:
    any of them
}