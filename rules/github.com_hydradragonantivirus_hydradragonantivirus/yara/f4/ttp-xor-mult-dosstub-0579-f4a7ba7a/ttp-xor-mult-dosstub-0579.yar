rule TTP_XOR_MULT_DOSStub_0579 {
  strings:
    $key_0579 = { 51 11 [2] 25 09 [2] 62 0b [2] 25 1a [2] 6b 16 [2] 67 1c [2] 70 17 [2] 6b 59 [2] 56 }

  condition:
    any of them
}