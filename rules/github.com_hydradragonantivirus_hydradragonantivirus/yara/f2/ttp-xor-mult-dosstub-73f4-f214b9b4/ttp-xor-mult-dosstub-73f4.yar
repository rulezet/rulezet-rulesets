rule TTP_XOR_MULT_DOSStub_73f4 {
  strings:
    $key_73f4 = { 27 9c [2] 53 84 [2] 14 86 [2] 53 97 [2] 1d 9b [2] 11 91 [2] 06 9a [2] 1d d4 [2] 20 }

  condition:
    any of them
}