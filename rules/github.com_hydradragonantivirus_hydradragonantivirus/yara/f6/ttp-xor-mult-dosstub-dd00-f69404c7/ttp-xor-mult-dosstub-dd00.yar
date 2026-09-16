rule TTP_XOR_MULT_DOSStub_dd00 {
  strings:
    $key_dd00 = { 89 68 [2] fd 70 [2] ba 72 [2] fd 63 [2] b3 6f [2] bf 65 [2] a8 6e [2] b3 20 [2] 8e }

  condition:
    any of them
}