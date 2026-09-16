rule TTP_XOR_MULT_DOSStub_0968 {
  strings:
    $key_0968 = { 5d 00 [2] 29 18 [2] 6e 1a [2] 29 0b [2] 67 07 [2] 6b 0d [2] 7c 06 [2] 67 48 [2] 5a }

  condition:
    any of them
}