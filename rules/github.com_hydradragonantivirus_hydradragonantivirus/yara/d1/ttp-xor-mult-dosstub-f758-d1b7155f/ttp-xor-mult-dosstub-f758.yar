rule TTP_XOR_MULT_DOSStub_f758 {
  strings:
    $key_f758 = { a3 30 [2] d7 28 [2] 90 2a [2] d7 3b [2] 99 37 [2] 95 3d [2] 82 36 [2] 99 78 [2] a4 }

  condition:
    any of them
}