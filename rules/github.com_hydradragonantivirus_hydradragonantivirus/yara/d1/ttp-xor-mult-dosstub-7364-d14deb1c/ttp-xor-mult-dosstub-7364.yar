rule TTP_XOR_MULT_DOSStub_7364 {
  strings:
    $key_7364 = { 27 0c [2] 53 14 [2] 14 16 [2] 53 07 [2] 1d 0b [2] 11 01 [2] 06 0a [2] 1d 44 [2] 20 }

  condition:
    any of them
}