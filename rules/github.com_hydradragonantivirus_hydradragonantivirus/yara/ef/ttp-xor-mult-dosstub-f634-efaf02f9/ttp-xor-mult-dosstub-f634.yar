rule TTP_XOR_MULT_DOSStub_f634 {
  strings:
    $key_f634 = { a2 5c [2] d6 44 [2] 91 46 [2] d6 57 [2] 98 5b [2] 94 51 [2] 83 5a [2] 98 14 [2] a5 }

  condition:
    any of them
}