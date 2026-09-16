rule TTP_XOR_MULT_DOSStub_f262 {
  strings:
    $key_f262 = { a6 0a [2] d2 12 [2] 95 10 [2] d2 01 [2] 9c 0d [2] 90 07 [2] 87 0c [2] 9c 42 [2] a1 }

  condition:
    any of them
}