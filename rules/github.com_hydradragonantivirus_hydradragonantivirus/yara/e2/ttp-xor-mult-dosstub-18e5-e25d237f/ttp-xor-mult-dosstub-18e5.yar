rule TTP_XOR_MULT_DOSStub_18e5 {
  strings:
    $key_18e5 = { 4c 8d [2] 38 95 [2] 7f 97 [2] 38 86 [2] 76 8a [2] 7a 80 [2] 6d 8b [2] 76 c5 [2] 4b }

  condition:
    any of them
}