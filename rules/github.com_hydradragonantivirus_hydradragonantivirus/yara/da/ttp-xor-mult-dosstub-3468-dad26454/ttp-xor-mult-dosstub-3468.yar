rule TTP_XOR_MULT_DOSStub_3468 {
  strings:
    $key_3468 = { 60 00 [2] 14 18 [2] 53 1a [2] 14 0b [2] 5a 07 [2] 56 0d [2] 41 06 [2] 5a 48 [2] 67 }

  condition:
    any of them
}