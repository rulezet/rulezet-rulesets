rule TTP_XOR_MULT_DOSStub_f3c0 {
  strings:
    $key_f3c0 = { a7 a8 [2] d3 b0 [2] 94 b2 [2] d3 a3 [2] 9d af [2] 91 a5 [2] 86 ae [2] 9d e0 [2] a0 }

  condition:
    any of them
}