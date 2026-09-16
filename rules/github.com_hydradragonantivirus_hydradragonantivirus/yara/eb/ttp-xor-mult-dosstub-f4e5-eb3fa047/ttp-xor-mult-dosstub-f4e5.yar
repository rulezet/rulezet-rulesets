rule TTP_XOR_MULT_DOSStub_f4e5 {
  strings:
    $key_f4e5 = { a0 8d [2] d4 95 [2] 93 97 [2] d4 86 [2] 9a 8a [2] 96 80 [2] 81 8b [2] 9a c5 [2] a7 }

  condition:
    any of them
}