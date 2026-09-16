rule TTP_XOR_MULT_DOSStub_f628 {
  strings:
    $key_f628 = { a2 40 [2] d6 58 [2] 91 5a [2] d6 4b [2] 98 47 [2] 94 4d [2] 83 46 [2] 98 08 [2] a5 }

  condition:
    any of them
}