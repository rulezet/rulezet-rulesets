rule TTP_XOR_MULT_DOSStub_73e5 {
  strings:
    $key_73e5 = { 27 8d [2] 53 95 [2] 14 97 [2] 53 86 [2] 1d 8a [2] 11 80 [2] 06 8b [2] 1d c5 [2] 20 }

  condition:
    any of them
}