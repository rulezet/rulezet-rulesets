rule TTP_XOR_MULT_DOSStub_b10e {
  strings:
    $key_b10e = { e5 66 [2] 91 7e [2] d6 7c [2] 91 6d [2] df 61 [2] d3 6b [2] c4 60 [2] df 2e [2] e2 }

  condition:
    any of them
}