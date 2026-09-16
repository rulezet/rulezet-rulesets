rule TTP_XOR_MULT_DOSStub_f702 {
  strings:
    $key_f702 = { a3 6a [2] d7 72 [2] 90 70 [2] d7 61 [2] 99 6d [2] 95 67 [2] 82 6c [2] 99 22 [2] a4 }

  condition:
    any of them
}