rule TTP_XOR_MULT_DOSStub_b1ee {
  strings:
    $key_b1ee = { e5 86 [2] 91 9e [2] d6 9c [2] 91 8d [2] df 81 [2] d3 8b [2] c4 80 [2] df ce [2] e2 }

  condition:
    any of them
}