rule TTP_XOR_MULT_DOSStub_4602 {
  strings:
    $key_4602 = { 12 6a [2] 66 72 [2] 21 70 [2] 66 61 [2] 28 6d [2] 24 67 [2] 33 6c [2] 28 22 [2] 15 }

  condition:
    any of them
}