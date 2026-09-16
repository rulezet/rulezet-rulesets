rule TTP_XOR_MULT_DOSStub_70e1 {
  strings:
    $key_70e1 = { 24 89 [2] 50 91 [2] 17 93 [2] 50 82 [2] 1e 8e [2] 12 84 [2] 05 8f [2] 1e c1 [2] 23 }

  condition:
    any of them
}