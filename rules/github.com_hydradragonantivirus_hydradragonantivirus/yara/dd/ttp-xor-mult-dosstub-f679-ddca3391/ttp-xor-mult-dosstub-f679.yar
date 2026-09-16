rule TTP_XOR_MULT_DOSStub_f679 {
  strings:
    $key_f679 = { a2 11 [2] d6 09 [2] 91 0b [2] d6 1a [2] 98 16 [2] 94 1c [2] 83 17 [2] 98 59 [2] a5 }

  condition:
    any of them
}