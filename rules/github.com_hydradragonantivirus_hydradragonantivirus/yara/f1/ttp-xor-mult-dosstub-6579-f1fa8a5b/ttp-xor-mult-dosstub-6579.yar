rule TTP_XOR_MULT_DOSStub_6579 {
  strings:
    $key_6579 = { 31 11 [2] 45 09 [2] 02 0b [2] 45 1a [2] 0b 16 [2] 07 1c [2] 10 17 [2] 0b 59 [2] 36 }

  condition:
    any of them
}