rule TTP_XOR_MULT_DOSStub_f139 {
  strings:
    $key_f139 = { a5 51 [2] d1 49 [2] 96 4b [2] d1 5a [2] 9f 56 [2] 93 5c [2] 84 57 [2] 9f 19 [2] a2 }

  condition:
    any of them
}