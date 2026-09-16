rule TTP_XOR_MULT_DOSStub_f4f4 {
  strings:
    $key_f4f4 = { a0 9c [2] d4 84 [2] 93 86 [2] d4 97 [2] 9a 9b [2] 96 91 [2] 81 9a [2] 9a d4 [2] a7 }

  condition:
    any of them
}