rule TTP_XOR_MULT_DOSStub_b161 {
  strings:
    $key_b161 = { e5 09 [2] 91 11 [2] d6 13 [2] 91 02 [2] df 0e [2] d3 04 [2] c4 0f [2] df 41 [2] e2 }

  condition:
    any of them
}