rule TTP_XOR_MULT_DOSStub_c3cb {
  strings:
    $key_c3cb = { 97 a3 [2] e3 bb [2] a4 b9 [2] e3 a8 [2] ad a4 [2] a1 ae [2] b6 a5 [2] ad eb [2] 90 }

  condition:
    any of them
}