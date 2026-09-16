rule TTP_XOR_MULT_DOSStub_b158 {
  strings:
    $key_b158 = { e5 30 [2] 91 28 [2] d6 2a [2] 91 3b [2] df 37 [2] d3 3d [2] c4 36 [2] df 78 [2] e2 }

  condition:
    any of them
}