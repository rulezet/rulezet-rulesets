rule TTP_XOR_MULT_DOSStub_f5e1 {
  strings:
    $key_f5e1 = { a1 89 [2] d5 91 [2] 92 93 [2] d5 82 [2] 9b 8e [2] 97 84 [2] 80 8f [2] 9b c1 [2] a6 }

  condition:
    any of them
}