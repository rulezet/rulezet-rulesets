rule TTP_XOR_MULT_DOSStub_b4fe {
  strings:
    $key_b4fe = { e0 96 [2] 94 8e [2] d3 8c [2] 94 9d [2] da 91 [2] d6 9b [2] c1 90 [2] da de [2] e7 }

  condition:
    any of them
}