rule TTP_XOR_MULT_DOSStub_b16f {
  strings:
    $key_b16f = { e5 07 [2] 91 1f [2] d6 1d [2] 91 0c [2] df 00 [2] d3 0a [2] c4 01 [2] df 4f [2] e2 }

  condition:
    any of them
}