rule TTP_XOR_MULT_DOSStub_b133 {
  strings:
    $key_b133 = { e5 5b [2] 91 43 [2] d6 41 [2] 91 50 [2] df 5c [2] d3 56 [2] c4 5d [2] df 13 [2] e2 }

  condition:
    any of them
}