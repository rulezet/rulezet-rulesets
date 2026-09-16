rule TTP_XOR_MULT_DOSStub_0202 {
  strings:
    $key_0202 = { 56 6a [2] 22 72 [2] 65 70 [2] 22 61 [2] 6c 6d [2] 60 67 [2] 77 6c [2] 6c 22 [2] 51 }

  condition:
    any of them
}