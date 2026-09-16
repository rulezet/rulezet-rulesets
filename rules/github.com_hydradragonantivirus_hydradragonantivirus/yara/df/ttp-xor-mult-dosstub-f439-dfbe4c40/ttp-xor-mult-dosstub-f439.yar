rule TTP_XOR_MULT_DOSStub_f439 {
  strings:
    $key_f439 = { a0 51 [2] d4 49 [2] 93 4b [2] d4 5a [2] 9a 56 [2] 96 5c [2] 81 57 [2] 9a 19 [2] a7 }

  condition:
    any of them
}