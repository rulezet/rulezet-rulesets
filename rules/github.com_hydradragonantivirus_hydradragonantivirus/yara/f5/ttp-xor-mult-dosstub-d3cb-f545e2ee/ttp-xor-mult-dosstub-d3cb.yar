rule TTP_XOR_MULT_DOSStub_d3cb {
  strings:
    $key_d3cb = { 87 a3 [2] f3 bb [2] b4 b9 [2] f3 a8 [2] bd a4 [2] b1 ae [2] a6 a5 [2] bd eb [2] 80 }

  condition:
    any of them
}