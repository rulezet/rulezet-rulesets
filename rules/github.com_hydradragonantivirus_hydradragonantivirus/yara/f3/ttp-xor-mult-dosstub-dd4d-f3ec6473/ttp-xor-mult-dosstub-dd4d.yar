rule TTP_XOR_MULT_DOSStub_dd4d {
  strings:
    $key_dd4d = { 89 25 [2] fd 3d [2] ba 3f [2] fd 2e [2] b3 22 [2] bf 28 [2] a8 23 [2] b3 6d [2] 8e }

  condition:
    any of them
}