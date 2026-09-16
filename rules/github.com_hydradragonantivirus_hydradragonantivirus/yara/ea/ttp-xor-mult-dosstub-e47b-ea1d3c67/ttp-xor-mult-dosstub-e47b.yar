rule TTP_XOR_MULT_DOSStub_e47b {
  strings:
    $key_e47b = { b0 13 [2] c4 0b [2] 83 09 [2] c4 18 [2] 8a 14 [2] 86 1e [2] 91 15 [2] 8a 5b [2] b7 }

  condition:
    any of them
}