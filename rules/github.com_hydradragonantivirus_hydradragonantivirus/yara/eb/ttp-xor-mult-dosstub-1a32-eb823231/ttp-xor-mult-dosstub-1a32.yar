rule TTP_XOR_MULT_DOSStub_1a32 {
  strings:
    $key_1a32 = { 4e 5a [2] 3a 42 [2] 7d 40 [2] 3a 51 [2] 74 5d [2] 78 57 [2] 6f 5c [2] 74 12 [2] 49 }

  condition:
    any of them
}