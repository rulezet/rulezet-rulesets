rule TTP_XOR_MULT_DOSStub_e45b {
  strings:
    $key_e45b = { b0 33 [2] c4 2b [2] 83 29 [2] c4 38 [2] 8a 34 [2] 86 3e [2] 91 35 [2] 8a 7b [2] b7 }

  condition:
    any of them
}