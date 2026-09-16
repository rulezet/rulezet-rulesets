rule TTP_XOR_MULT_DOSStub_b17b {
  strings:
    $key_b17b = { e5 13 [2] 91 0b [2] d6 09 [2] 91 18 [2] df 14 [2] d3 1e [2] c4 15 [2] df 5b [2] e2 }

  condition:
    any of them
}