rule TTP_XOR_MULT_DOSStub_dd05 {
  strings:
    $key_dd05 = { 89 6d [2] fd 75 [2] ba 77 [2] fd 66 [2] b3 6a [2] bf 60 [2] a8 6b [2] b3 25 [2] 8e }

  condition:
    any of them
}