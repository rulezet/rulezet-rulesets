rule TTP_XOR_MULT_DOSStub_f235 {
  strings:
    $key_f235 = { a6 5d [2] d2 45 [2] 95 47 [2] d2 56 [2] 9c 5a [2] 90 50 [2] 87 5b [2] 9c 15 [2] a1 }

  condition:
    any of them
}