rule TTP_XOR_MULT_DOSStub_dd66 {
  strings:
    $key_dd66 = { 89 0e [2] fd 16 [2] ba 14 [2] fd 05 [2] b3 09 [2] bf 03 [2] a8 08 [2] b3 46 [2] 8e }

  condition:
    any of them
}