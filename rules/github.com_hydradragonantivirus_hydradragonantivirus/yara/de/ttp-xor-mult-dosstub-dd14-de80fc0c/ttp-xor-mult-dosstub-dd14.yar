rule TTP_XOR_MULT_DOSStub_dd14 {
  strings:
    $key_dd14 = { 89 7c [2] fd 64 [2] ba 66 [2] fd 77 [2] b3 7b [2] bf 71 [2] a8 7a [2] b3 34 [2] 8e }

  condition:
    any of them
}