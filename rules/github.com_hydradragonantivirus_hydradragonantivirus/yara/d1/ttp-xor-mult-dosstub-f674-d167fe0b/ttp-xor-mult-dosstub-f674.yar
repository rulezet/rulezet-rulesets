rule TTP_XOR_MULT_DOSStub_f674 {
  strings:
    $key_f674 = { a2 1c [2] d6 04 [2] 91 06 [2] d6 17 [2] 98 1b [2] 94 11 [2] 83 1a [2] 98 54 [2] a5 }

  condition:
    any of them
}