rule TTP_XOR_MULT_DOSStub_b179 {
  strings:
    $key_b179 = { e5 11 [2] 91 09 [2] d6 0b [2] 91 1a [2] df 16 [2] d3 1c [2] c4 17 [2] df 59 [2] e2 }

  condition:
    any of them
}