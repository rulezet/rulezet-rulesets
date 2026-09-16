rule TTP_XOR_MULT_DOSStub_76e5 {
  strings:
    $key_76e5 = { 22 8d [2] 56 95 [2] 11 97 [2] 56 86 [2] 18 8a [2] 14 80 [2] 03 8b [2] 18 c5 [2] 25 }

  condition:
    any of them
}