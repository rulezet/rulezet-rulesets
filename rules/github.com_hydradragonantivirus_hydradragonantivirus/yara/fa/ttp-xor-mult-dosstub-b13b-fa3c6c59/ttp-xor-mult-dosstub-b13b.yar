rule TTP_XOR_MULT_DOSStub_b13b {
  strings:
    $key_b13b = { e5 53 [2] 91 4b [2] d6 49 [2] 91 58 [2] df 54 [2] d3 5e [2] c4 55 [2] df 1b [2] e2 }

  condition:
    any of them
}