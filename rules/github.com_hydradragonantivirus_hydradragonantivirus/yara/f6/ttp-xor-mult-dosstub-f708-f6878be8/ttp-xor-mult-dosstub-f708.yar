rule TTP_XOR_MULT_DOSStub_f708 {
  strings:
    $key_f708 = { a3 60 [2] d7 78 [2] 90 7a [2] d7 6b [2] 99 67 [2] 95 6d [2] 82 66 [2] 99 28 [2] a4 }

  condition:
    any of them
}