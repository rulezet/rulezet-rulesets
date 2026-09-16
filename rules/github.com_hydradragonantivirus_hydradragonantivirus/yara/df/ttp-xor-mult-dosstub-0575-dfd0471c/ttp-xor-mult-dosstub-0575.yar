rule TTP_XOR_MULT_DOSStub_0575 {
  strings:
    $key_0575 = { 51 1d [2] 25 05 [2] 62 07 [2] 25 16 [2] 6b 1a [2] 67 10 [2] 70 1b [2] 6b 55 [2] 56 }

  condition:
    any of them
}