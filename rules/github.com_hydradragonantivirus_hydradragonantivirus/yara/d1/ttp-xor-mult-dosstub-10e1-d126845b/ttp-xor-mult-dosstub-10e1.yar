rule TTP_XOR_MULT_DOSStub_10e1 {
  strings:
    $key_10e1 = { 44 89 [2] 30 91 [2] 77 93 [2] 30 82 [2] 7e 8e [2] 72 84 [2] 65 8f [2] 7e c1 [2] 43 }

  condition:
    any of them
}