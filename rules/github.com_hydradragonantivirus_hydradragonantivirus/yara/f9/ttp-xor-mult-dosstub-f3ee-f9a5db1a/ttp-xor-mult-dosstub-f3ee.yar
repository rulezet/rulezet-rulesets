rule TTP_XOR_MULT_DOSStub_f3ee {
  strings:
    $key_f3ee = { a7 86 [2] d3 9e [2] 94 9c [2] d3 8d [2] 9d 81 [2] 91 8b [2] 86 80 [2] 9d ce [2] a0 }

  condition:
    any of them
}