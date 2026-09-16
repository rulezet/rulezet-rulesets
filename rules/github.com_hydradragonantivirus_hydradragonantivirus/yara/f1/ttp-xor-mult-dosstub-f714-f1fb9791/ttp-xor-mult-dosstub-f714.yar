rule TTP_XOR_MULT_DOSStub_f714 {
  strings:
    $key_f714 = { a3 7c [2] d7 64 [2] 90 66 [2] d7 77 [2] 99 7b [2] 95 71 [2] 82 7a [2] 99 34 [2] a4 }

  condition:
    any of them
}