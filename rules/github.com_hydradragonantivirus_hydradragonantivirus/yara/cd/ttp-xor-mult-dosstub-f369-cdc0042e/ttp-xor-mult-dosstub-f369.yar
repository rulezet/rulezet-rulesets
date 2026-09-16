rule TTP_XOR_MULT_DOSStub_f369 {
  strings:
    $key_f369 = { a7 01 [2] d3 19 [2] 94 1b [2] d3 0a [2] 9d 06 [2] 91 0c [2] 86 07 [2] 9d 49 [2] a0 }

  condition:
    any of them
}