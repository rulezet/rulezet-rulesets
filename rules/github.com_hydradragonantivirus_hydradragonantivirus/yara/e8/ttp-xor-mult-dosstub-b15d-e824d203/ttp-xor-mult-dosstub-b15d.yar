rule TTP_XOR_MULT_DOSStub_b15d {
  strings:
    $key_b15d = { e5 35 [2] 91 2d [2] d6 2f [2] 91 3e [2] df 32 [2] d3 38 [2] c4 33 [2] df 7d [2] e2 }

  condition:
    any of them
}