rule TTP_XOR_MULT_DOSStub_dd7e {
  strings:
    $key_dd7e = { 89 16 [2] fd 0e [2] ba 0c [2] fd 1d [2] b3 11 [2] bf 1b [2] a8 10 [2] b3 5e [2] 8e }

  condition:
    any of them
}