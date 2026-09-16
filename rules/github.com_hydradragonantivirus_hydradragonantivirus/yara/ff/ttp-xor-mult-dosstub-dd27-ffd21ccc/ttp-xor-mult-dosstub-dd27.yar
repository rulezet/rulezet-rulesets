rule TTP_XOR_MULT_DOSStub_dd27 {
  strings:
    $key_dd27 = { 89 4f [2] fd 57 [2] ba 55 [2] fd 44 [2] b3 48 [2] bf 42 [2] a8 49 [2] b3 07 [2] 8e }

  condition:
    any of them
}