rule TTP_XOR_MULT_DOSStub_f238 {
  strings:
    $key_f238 = { a6 50 [2] d2 48 [2] 95 4a [2] d2 5b [2] 9c 57 [2] 90 5d [2] 87 56 [2] 9c 18 [2] a1 }

  condition:
    any of them
}