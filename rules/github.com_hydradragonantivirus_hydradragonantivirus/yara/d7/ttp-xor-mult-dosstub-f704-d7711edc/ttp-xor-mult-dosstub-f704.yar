rule TTP_XOR_MULT_DOSStub_f704 {
  strings:
    $key_f704 = { a3 6c [2] d7 74 [2] 90 76 [2] d7 67 [2] 99 6b [2] 95 61 [2] 82 6a [2] 99 24 [2] a4 }

  condition:
    any of them
}