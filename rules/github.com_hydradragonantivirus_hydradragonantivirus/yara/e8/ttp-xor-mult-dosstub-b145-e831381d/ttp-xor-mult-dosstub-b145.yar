rule TTP_XOR_MULT_DOSStub_b145 {
  strings:
    $key_b145 = { e5 2d [2] 91 35 [2] d6 37 [2] 91 26 [2] df 2a [2] d3 20 [2] c4 2b [2] df 65 [2] e2 }

  condition:
    any of them
}