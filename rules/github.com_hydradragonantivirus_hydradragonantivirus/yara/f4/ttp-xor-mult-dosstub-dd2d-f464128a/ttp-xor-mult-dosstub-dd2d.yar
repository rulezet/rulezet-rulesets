rule TTP_XOR_MULT_DOSStub_dd2d {
  strings:
    $key_dd2d = { 89 45 [2] fd 5d [2] ba 5f [2] fd 4e [2] b3 42 [2] bf 48 [2] a8 43 [2] b3 0d [2] 8e }

  condition:
    any of them
}