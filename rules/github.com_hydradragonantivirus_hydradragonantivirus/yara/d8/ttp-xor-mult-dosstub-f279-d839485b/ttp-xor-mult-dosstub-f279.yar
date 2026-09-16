rule TTP_XOR_MULT_DOSStub_f279 {
  strings:
    $key_f279 = { a6 11 [2] d2 09 [2] 95 0b [2] d2 1a [2] 9c 16 [2] 90 1c [2] 87 17 [2] 9c 59 [2] a1 }

  condition:
    any of them
}