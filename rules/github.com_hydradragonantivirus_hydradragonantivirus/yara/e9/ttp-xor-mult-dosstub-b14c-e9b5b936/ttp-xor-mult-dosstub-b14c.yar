rule TTP_XOR_MULT_DOSStub_b14c {
  strings:
    $key_b14c = { e5 24 [2] 91 3c [2] d6 3e [2] 91 2f [2] df 23 [2] d3 29 [2] c4 22 [2] df 6c [2] e2 }

  condition:
    any of them
}