rule TTP_XOR_MULT_DOSStub_f1e7 {
  strings:
    $key_f1e7 = { a5 8f [2] d1 97 [2] 96 95 [2] d1 84 [2] 9f 88 [2] 93 82 [2] 84 89 [2] 9f c7 [2] a2 }

  condition:
    any of them
}