rule TTP_XOR_MULT_DOSStub_e27b {
  strings:
    $key_e27b = { b6 13 [2] c2 0b [2] 85 09 [2] c2 18 [2] 8c 14 [2] 80 1e [2] 97 15 [2] 8c 5b [2] b1 }

  condition:
    any of them
}