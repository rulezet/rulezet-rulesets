rule TTP_XOR_MULT_DOSStub_62e5 {
  strings:
    $key_62e5 = { 36 8d [2] 42 95 [2] 05 97 [2] 42 86 [2] 0c 8a [2] 00 80 [2] 17 8b [2] 0c c5 [2] 31 }

  condition:
    any of them
}