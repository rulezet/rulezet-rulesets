rule TTP_XOR_MULT_DOSStub_dd7d {
  strings:
    $key_dd7d = { 89 15 [2] fd 0d [2] ba 0f [2] fd 1e [2] b3 12 [2] bf 18 [2] a8 13 [2] b3 5d [2] 8e }

  condition:
    any of them
}