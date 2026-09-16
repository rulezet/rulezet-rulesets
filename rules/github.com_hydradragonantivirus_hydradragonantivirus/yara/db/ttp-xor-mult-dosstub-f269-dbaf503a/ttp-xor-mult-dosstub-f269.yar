rule TTP_XOR_MULT_DOSStub_f269 {
  strings:
    $key_f269 = { a6 01 [2] d2 19 [2] 95 1b [2] d2 0a [2] 9c 06 [2] 90 0c [2] 87 07 [2] 9c 49 [2] a1 }

  condition:
    any of them
}