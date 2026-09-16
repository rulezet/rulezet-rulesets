rule TTP_XOR_MULT_DOSStub_dd22 {
  strings:
    $key_dd22 = { 89 4a [2] fd 52 [2] ba 50 [2] fd 41 [2] b3 4d [2] bf 47 [2] a8 4c [2] b3 02 [2] 8e }

  condition:
    any of them
}