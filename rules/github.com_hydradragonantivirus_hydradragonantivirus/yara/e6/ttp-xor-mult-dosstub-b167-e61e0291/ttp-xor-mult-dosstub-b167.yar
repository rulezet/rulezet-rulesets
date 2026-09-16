rule TTP_XOR_MULT_DOSStub_b167 {
  strings:
    $key_b167 = { e5 0f [2] 91 17 [2] d6 15 [2] 91 04 [2] df 08 [2] d3 02 [2] c4 09 [2] df 47 [2] e2 }

  condition:
    any of them
}