rule TTP_XOR_MULT_DOSStub_1ae5 {
  strings:
    $key_1ae5 = { 4e 8d [2] 3a 95 [2] 7d 97 [2] 3a 86 [2] 74 8a [2] 78 80 [2] 6f 8b [2] 74 c5 [2] 49 }

  condition:
    any of them
}