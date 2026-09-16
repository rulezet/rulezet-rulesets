rule TTP_XOR_MULT_DOSStub_f574 {
  strings:
    $key_f574 = { a1 1c [2] d5 04 [2] 92 06 [2] d5 17 [2] 9b 1b [2] 97 11 [2] 80 1a [2] 9b 54 [2] a6 }

  condition:
    any of them
}