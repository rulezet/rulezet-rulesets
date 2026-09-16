rule TTP_XOR_MULT_DOSStub_dd50 {
  strings:
    $key_dd50 = { 89 38 [2] fd 20 [2] ba 22 [2] fd 33 [2] b3 3f [2] bf 35 [2] a8 3e [2] b3 70 [2] 8e }

  condition:
    any of them
}