rule TTP_XOR_MULT_DOSStub_b13f {
  strings:
    $key_b13f = { e5 57 [2] 91 4f [2] d6 4d [2] 91 5c [2] df 50 [2] d3 5a [2] c4 51 [2] df 1f [2] e2 }

  condition:
    any of them
}