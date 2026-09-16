rule TTP_XOR_MULT_DOSStub_f169 {
  strings:
    $key_f169 = { a5 01 [2] d1 19 [2] 96 1b [2] d1 0a [2] 9f 06 [2] 93 0c [2] 84 07 [2] 9f 49 [2] a2 }

  condition:
    any of them
}