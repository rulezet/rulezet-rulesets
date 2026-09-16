rule TTP_XOR_MULT_DOSStub_b105 {
  strings:
    $key_b105 = { e5 6d [2] 91 75 [2] d6 77 [2] 91 66 [2] df 6a [2] d3 60 [2] c4 6b [2] df 25 [2] e2 }

  condition:
    any of them
}