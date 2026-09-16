rule TTP_XOR_MULT_DOSStub_b1f2 {
  strings:
    $key_b1f2 = { e5 9a [2] 91 82 [2] d6 80 [2] 91 91 [2] df 9d [2] d3 97 [2] c4 9c [2] df d2 [2] e2 }

  condition:
    any of them
}