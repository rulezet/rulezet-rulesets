rule TTP_XOR_MULT_DOSStub_dd20 {
  strings:
    $key_dd20 = { 89 48 [2] fd 50 [2] ba 52 [2] fd 43 [2] b3 4f [2] bf 45 [2] a8 4e [2] b3 00 [2] 8e }

  condition:
    any of them
}