rule TTP_XOR_MULT_DOSStub_f664 {
  strings:
    $key_f664 = { a2 0c [2] d6 14 [2] 91 16 [2] d6 07 [2] 98 0b [2] 94 01 [2] 83 0a [2] 98 44 [2] a5 }

  condition:
    any of them
}