rule TTP_XOR_MULT_DOSStub_b125 {
  strings:
    $key_b125 = { e5 4d [2] 91 55 [2] d6 57 [2] 91 46 [2] df 4a [2] d3 40 [2] c4 4b [2] df 05 [2] e2 }

  condition:
    any of them
}