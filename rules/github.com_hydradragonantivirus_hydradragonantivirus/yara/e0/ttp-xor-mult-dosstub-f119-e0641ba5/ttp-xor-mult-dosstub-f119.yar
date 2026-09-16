rule TTP_XOR_MULT_DOSStub_f119 {
  strings:
    $key_f119 = { a5 71 [2] d1 69 [2] 96 6b [2] d1 7a [2] 9f 76 [2] 93 7c [2] 84 77 [2] 9f 39 [2] a2 }

  condition:
    any of them
}