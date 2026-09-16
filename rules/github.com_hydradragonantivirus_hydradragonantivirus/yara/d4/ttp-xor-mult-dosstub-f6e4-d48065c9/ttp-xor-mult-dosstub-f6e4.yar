rule TTP_XOR_MULT_DOSStub_f6e4 {
  strings:
    $key_f6e4 = { a2 8c [2] d6 94 [2] 91 96 [2] d6 87 [2] 98 8b [2] 94 81 [2] 83 8a [2] 98 c4 [2] a5 }

  condition:
    any of them
}