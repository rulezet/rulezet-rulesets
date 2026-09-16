rule TTP_XOR_MULT_DOSStub_f264 {
  strings:
    $key_f264 = { a6 0c [2] d2 14 [2] 95 16 [2] d2 07 [2] 9c 0b [2] 90 01 [2] 87 0a [2] 9c 44 [2] a1 }

  condition:
    any of them
}