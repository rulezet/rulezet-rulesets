rule TTP_XOR_MULT_DOSStub_4332 {
  strings:
    $key_4332 = { 17 5a [2] 63 42 [2] 24 40 [2] 63 51 [2] 2d 5d [2] 21 57 [2] 36 5c [2] 2d 12 [2] 10 }

  condition:
    any of them
}