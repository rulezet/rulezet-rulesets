rule TTP_XOR_MULT_DOSStub_dd46 {
  strings:
    $key_dd46 = { 89 2e [2] fd 36 [2] ba 34 [2] fd 25 [2] b3 29 [2] bf 23 [2] a8 28 [2] b3 66 [2] 8e }

  condition:
    any of them
}