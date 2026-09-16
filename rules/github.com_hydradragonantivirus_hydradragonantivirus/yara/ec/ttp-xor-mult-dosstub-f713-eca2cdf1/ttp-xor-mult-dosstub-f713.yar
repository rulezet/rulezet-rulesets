rule TTP_XOR_MULT_DOSStub_f713 {
  strings:
    $key_f713 = { a3 7b [2] d7 63 [2] 90 61 [2] d7 70 [2] 99 7c [2] 95 76 [2] 82 7d [2] 99 33 [2] a4 }

  condition:
    any of them
}