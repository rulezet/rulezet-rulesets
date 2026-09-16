rule TTP_XOR_MULT_DOSStub_03e8 {
  strings:
    $key_03e8 = { 57 80 [2] 23 98 [2] 64 9a [2] 23 8b [2] 6d 87 [2] 61 8d [2] 76 86 [2] 6d c8 [2] 50 }

  condition:
    any of them
}