rule TTP_XOR_MULT_DOSStub_d5cb {
  strings:
    $key_d5cb = { 81 a3 [2] f5 bb [2] b2 b9 [2] f5 a8 [2] bb a4 [2] b7 ae [2] a0 a5 [2] bb eb [2] 86 }

  condition:
    any of them
}