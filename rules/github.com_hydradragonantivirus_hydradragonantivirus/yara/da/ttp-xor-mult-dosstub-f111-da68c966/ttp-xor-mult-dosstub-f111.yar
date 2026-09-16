rule TTP_XOR_MULT_DOSStub_f111 {
  strings:
    $key_f111 = { a5 79 [2] d1 61 [2] 96 63 [2] d1 72 [2] 9f 7e [2] 93 74 [2] 84 7f [2] 9f 31 [2] a2 }

  condition:
    any of them
}