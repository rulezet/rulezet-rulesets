rule TTP_XOR_MULT_DOSStub_d49b {
  strings:
    $key_d49b = { 80 f3 [2] f4 eb [2] b3 e9 [2] f4 f8 [2] ba f4 [2] b6 fe [2] a1 f5 [2] ba bb [2] 87 }

  condition:
    any of them
}