rule TTP_XOR_MULT_DOSStub_73e3 {
  strings:
    $key_73e3 = { 27 8b [2] 53 93 [2] 14 91 [2] 53 80 [2] 1d 8c [2] 11 86 [2] 06 8d [2] 1d c3 [2] 20 }

  condition:
    any of them
}