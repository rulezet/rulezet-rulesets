rule TTP_XOR_MULT_DOSStub_f678 {
  strings:
    $key_f678 = { a2 10 [2] d6 08 [2] 91 0a [2] d6 1b [2] 98 17 [2] 94 1d [2] 83 16 [2] 98 58 [2] a5 }

  condition:
    any of them
}