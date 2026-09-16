rule TTP_XOR_MULT_DOSStub_dd75 {
  strings:
    $key_dd75 = { 89 1d [2] fd 05 [2] ba 07 [2] fd 16 [2] b3 1a [2] bf 10 [2] a8 1b [2] b3 55 [2] 8e }

  condition:
    any of them
}