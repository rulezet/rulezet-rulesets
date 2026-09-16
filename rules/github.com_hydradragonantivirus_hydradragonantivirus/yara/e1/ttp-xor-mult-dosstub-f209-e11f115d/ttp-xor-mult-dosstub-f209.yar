rule TTP_XOR_MULT_DOSStub_f209 {
  strings:
    $key_f209 = { a6 61 [2] d2 79 [2] 95 7b [2] d2 6a [2] 9c 66 [2] 90 6c [2] 87 67 [2] 9c 29 [2] a1 }

  condition:
    any of them
}