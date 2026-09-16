rule TTP_XOR_MULT_DOSStub_f6f6 {
  strings:
    $key_f6f6 = { a2 9e [2] d6 86 [2] 91 84 [2] d6 95 [2] 98 99 [2] 94 93 [2] 83 98 [2] 98 d6 [2] a5 }

  condition:
    any of them
}