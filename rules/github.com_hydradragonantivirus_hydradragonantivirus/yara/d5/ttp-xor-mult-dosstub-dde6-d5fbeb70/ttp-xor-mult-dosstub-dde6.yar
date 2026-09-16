rule TTP_XOR_MULT_DOSStub_dde6 {
  strings:
    $key_dde6 = { 89 8e [2] fd 96 [2] ba 94 [2] fd 85 [2] b3 89 [2] bf 83 [2] a8 88 [2] b3 c6 [2] 8e }

  condition:
    any of them
}