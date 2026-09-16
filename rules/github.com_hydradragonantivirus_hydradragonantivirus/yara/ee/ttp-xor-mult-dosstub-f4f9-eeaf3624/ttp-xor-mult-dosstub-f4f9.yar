rule TTP_XOR_MULT_DOSStub_f4f9 {
  strings:
    $key_f4f9 = { a0 91 [2] d4 89 [2] 93 8b [2] d4 9a [2] 9a 96 [2] 96 9c [2] 81 97 [2] 9a d9 [2] a7 }

  condition:
    any of them
}