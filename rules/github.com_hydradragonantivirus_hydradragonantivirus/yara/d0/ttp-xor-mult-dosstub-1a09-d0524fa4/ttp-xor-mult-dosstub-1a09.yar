rule TTP_XOR_MULT_DOSStub_1a09 {
  strings:
    $key_1a09 = { 4e 61 [2] 3a 79 [2] 7d 7b [2] 3a 6a [2] 74 66 [2] 78 6c [2] 6f 67 [2] 74 29 [2] 49 }

  condition:
    any of them
}