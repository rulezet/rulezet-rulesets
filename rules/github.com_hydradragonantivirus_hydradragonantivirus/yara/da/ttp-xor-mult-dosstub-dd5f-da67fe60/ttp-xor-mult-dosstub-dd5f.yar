rule TTP_XOR_MULT_DOSStub_dd5f {
  strings:
    $key_dd5f = { 89 37 [2] fd 2f [2] ba 2d [2] fd 3c [2] b3 30 [2] bf 3a [2] a8 31 [2] b3 7f [2] 8e }

  condition:
    any of them
}