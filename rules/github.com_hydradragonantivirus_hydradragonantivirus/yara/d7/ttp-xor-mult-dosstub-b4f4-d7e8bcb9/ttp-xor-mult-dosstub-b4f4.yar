rule TTP_XOR_MULT_DOSStub_b4f4 {
  strings:
    $key_b4f4 = { e0 9c [2] 94 84 [2] d3 86 [2] 94 97 [2] da 9b [2] d6 91 [2] c1 9a [2] da d4 [2] e7 }

  condition:
    any of them
}