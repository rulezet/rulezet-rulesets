rule TTP_XOR_MULT_DOSStub_90de {
  strings:
    $key_90de = { c4 b6 [2] b0 ae [2] f7 ac [2] b0 bd [2] fe b1 [2] f2 bb [2] e5 b0 [2] fe fe [2] c3 }

  condition:
    any of them
}