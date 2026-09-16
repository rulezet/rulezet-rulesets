rule TTP_XOR_MULT_DOSStub_f178 {
  strings:
    $key_f178 = { a5 10 [2] d1 08 [2] 96 0a [2] d1 1b [2] 9f 17 [2] 93 1d [2] 84 16 [2] 9f 58 [2] a2 }

  condition:
    any of them
}