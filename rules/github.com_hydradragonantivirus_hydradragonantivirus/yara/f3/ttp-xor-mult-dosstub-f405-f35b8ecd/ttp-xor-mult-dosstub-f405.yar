rule TTP_XOR_MULT_DOSStub_f405 {
  strings:
    $key_f405 = { a0 6d [2] d4 75 [2] 93 77 [2] d4 66 [2] 9a 6a [2] 96 60 [2] 81 6b [2] 9a 25 [2] a7 }

  condition:
    any of them
}