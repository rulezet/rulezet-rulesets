rule TTP_XOR_MULT_DOSStub_b174 {
  strings:
    $key_b174 = { e5 1c [2] 91 04 [2] d6 06 [2] 91 17 [2] df 1b [2] d3 11 [2] c4 1a [2] df 54 [2] e2 }

  condition:
    any of them
}