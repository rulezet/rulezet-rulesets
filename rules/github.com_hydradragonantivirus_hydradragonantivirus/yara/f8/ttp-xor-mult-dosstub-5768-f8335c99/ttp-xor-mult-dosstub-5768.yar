rule TTP_XOR_MULT_DOSStub_5768 {
  strings:
    $key_5768 = { 03 00 [2] 77 18 [2] 30 1a [2] 77 0b [2] 39 07 [2] 35 0d [2] 22 06 [2] 39 48 [2] 04 }

  condition:
    any of them
}