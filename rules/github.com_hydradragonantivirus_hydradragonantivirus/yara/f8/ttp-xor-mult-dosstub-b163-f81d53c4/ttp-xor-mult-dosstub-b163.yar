rule TTP_XOR_MULT_DOSStub_b163 {
  strings:
    $key_b163 = { e5 0b [2] 91 13 [2] d6 11 [2] 91 00 [2] df 0c [2] d3 06 [2] c4 0d [2] df 43 [2] e2 }

  condition:
    any of them
}