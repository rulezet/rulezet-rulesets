rule TTP_XOR_MULT_DOSStub_0311 {
  strings:
    $key_0311 = { 57 79 [2] 23 61 [2] 64 63 [2] 23 72 [2] 6d 7e [2] 61 74 [2] 76 7f [2] 6d 31 [2] 50 }

  condition:
    any of them
}