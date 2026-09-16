rule TTP_XOR_MULT_DOSStub_c5cb {
  strings:
    $key_c5cb = { 91 a3 [2] e5 bb [2] a2 b9 [2] e5 a8 [2] ab a4 [2] a7 ae [2] b0 a5 [2] ab eb [2] 96 }

  condition:
    any of them
}