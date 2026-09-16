rule TTP_XOR_MULT_DOSStub_7279 {
  strings:
    $key_7279 = { 26 11 [2] 52 09 [2] 15 0b [2] 52 1a [2] 1c 16 [2] 10 1c [2] 07 17 [2] 1c 59 [2] 21 }

  condition:
    any of them
}