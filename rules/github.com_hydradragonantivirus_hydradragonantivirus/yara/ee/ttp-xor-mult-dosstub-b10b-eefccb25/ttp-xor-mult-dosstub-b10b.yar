rule TTP_XOR_MULT_DOSStub_b10b {
  strings:
    $key_b10b = { e5 63 [2] 91 7b [2] d6 79 [2] 91 68 [2] df 64 [2] d3 6e [2] c4 65 [2] df 2b [2] e2 }

  condition:
    any of them
}