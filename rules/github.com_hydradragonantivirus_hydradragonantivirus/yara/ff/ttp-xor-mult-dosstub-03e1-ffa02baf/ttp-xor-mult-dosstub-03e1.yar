rule TTP_XOR_MULT_DOSStub_03e1 {
  strings:
    $key_03e1 = { 57 89 [2] 23 91 [2] 64 93 [2] 23 82 [2] 6d 8e [2] 61 84 [2] 76 8f [2] 6d c1 [2] 50 }

  condition:
    any of them
}