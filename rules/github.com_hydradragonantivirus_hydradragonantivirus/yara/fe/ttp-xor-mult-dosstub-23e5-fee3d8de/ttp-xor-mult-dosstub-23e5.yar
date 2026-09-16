rule TTP_XOR_MULT_DOSStub_23e5 {
  strings:
    $key_23e5 = { 77 8d [2] 03 95 [2] 44 97 [2] 03 86 [2] 4d 8a [2] 41 80 [2] 56 8b [2] 4d c5 [2] 70 }

  condition:
    any of them
}