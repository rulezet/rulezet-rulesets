rule TTP_XOR_MULT_DOSStub_dd5c {
  strings:
    $key_dd5c = { 89 34 [2] fd 2c [2] ba 2e [2] fd 3f [2] b3 33 [2] bf 39 [2] a8 32 [2] b3 7c [2] 8e }

  condition:
    any of them
}