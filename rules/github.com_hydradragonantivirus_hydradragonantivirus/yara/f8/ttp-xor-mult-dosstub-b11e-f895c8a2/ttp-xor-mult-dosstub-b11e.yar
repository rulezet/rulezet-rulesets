rule TTP_XOR_MULT_DOSStub_b11e {
  strings:
    $key_b11e = { e5 76 [2] 91 6e [2] d6 6c [2] 91 7d [2] df 71 [2] d3 7b [2] c4 70 [2] df 3e [2] e2 }

  condition:
    any of them
}