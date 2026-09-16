rule TTP_XOR_MULT_DOSStub_cacc {
  strings:
    $key_cacc = { 9e a4 [2] ea bc [2] ad be [2] ea af [2] a4 a3 [2] a8 a9 [2] bf a2 [2] a4 ec [2] 99 }

  condition:
    any of them
}