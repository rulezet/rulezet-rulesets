rule TTP_XOR_MULT_DOSStub_f649 {
  strings:
    $key_f649 = { a2 21 [2] d6 39 [2] 91 3b [2] d6 2a [2] 98 26 [2] 94 2c [2] 83 27 [2] 98 69 [2] a5 }

  condition:
    any of them
}