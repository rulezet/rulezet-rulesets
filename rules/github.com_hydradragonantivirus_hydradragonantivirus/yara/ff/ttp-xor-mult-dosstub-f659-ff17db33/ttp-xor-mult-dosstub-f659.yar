rule TTP_XOR_MULT_DOSStub_f659 {
  strings:
    $key_f659 = { a2 31 [2] d6 29 [2] 91 2b [2] d6 3a [2] 98 36 [2] 94 3c [2] 83 37 [2] 98 79 [2] a5 }

  condition:
    any of them
}