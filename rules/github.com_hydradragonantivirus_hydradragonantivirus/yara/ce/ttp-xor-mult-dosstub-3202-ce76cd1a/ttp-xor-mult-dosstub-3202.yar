rule TTP_XOR_MULT_DOSStub_3202 {
  strings:
    $key_3202 = { 66 6a [2] 12 72 [2] 55 70 [2] 12 61 [2] 5c 6d [2] 50 67 [2] 47 6c [2] 5c 22 [2] 61 }

  condition:
    any of them
}