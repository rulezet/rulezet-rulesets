rule TTP_XOR_MULT_DOSStub_45e5 {
  strings:
    $key_45e5 = { 11 8d [2] 65 95 [2] 22 97 [2] 65 86 [2] 2b 8a [2] 27 80 [2] 30 8b [2] 2b c5 [2] 16 }

  condition:
    any of them
}