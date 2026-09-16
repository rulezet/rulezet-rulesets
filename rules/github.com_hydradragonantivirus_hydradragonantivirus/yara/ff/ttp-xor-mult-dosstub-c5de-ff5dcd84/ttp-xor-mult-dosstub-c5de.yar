rule TTP_XOR_MULT_DOSStub_c5de {
  strings:
    $key_c5de = { 91 b6 [2] e5 ae [2] a2 ac [2] e5 bd [2] ab b1 [2] a7 bb [2] b0 b0 [2] ab fe [2] 96 }

  condition:
    any of them
}