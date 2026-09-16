rule TTP_XOR_MULT_DOSStub_0363 {
  strings:
    $key_0363 = { 57 0b [2] 23 13 [2] 64 11 [2] 23 00 [2] 6d 0c [2] 61 06 [2] 76 0d [2] 6d 43 [2] 50 }

  condition:
    any of them
}