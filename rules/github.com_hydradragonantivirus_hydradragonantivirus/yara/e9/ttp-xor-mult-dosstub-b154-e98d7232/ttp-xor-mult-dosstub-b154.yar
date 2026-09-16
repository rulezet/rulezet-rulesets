rule TTP_XOR_MULT_DOSStub_b154 {
  strings:
    $key_b154 = { e5 3c [2] 91 24 [2] d6 26 [2] 91 37 [2] df 3b [2] d3 31 [2] c4 3a [2] df 74 [2] e2 }

  condition:
    any of them
}