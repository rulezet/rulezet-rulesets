rule TTP_XOR_MULT_DOSStub_f724 {
  strings:
    $key_f724 = { a3 4c [2] d7 54 [2] 90 56 [2] d7 47 [2] 99 4b [2] 95 41 [2] 82 4a [2] 99 04 [2] a4 }

  condition:
    any of them
}