rule TTP_XOR_MULT_DOSStub_e67b {
  strings:
    $key_e67b = { b2 13 [2] c6 0b [2] 81 09 [2] c6 18 [2] 88 14 [2] 84 1e [2] 93 15 [2] 88 5b [2] b5 }

  condition:
    any of them
}