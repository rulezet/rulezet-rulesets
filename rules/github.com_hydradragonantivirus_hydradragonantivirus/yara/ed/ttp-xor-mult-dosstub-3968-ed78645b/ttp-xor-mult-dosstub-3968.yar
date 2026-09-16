rule TTP_XOR_MULT_DOSStub_3968 {
  strings:
    $key_3968 = { 6d 00 [2] 19 18 [2] 5e 1a [2] 19 0b [2] 57 07 [2] 5b 0d [2] 4c 06 [2] 57 48 [2] 6a }

  condition:
    any of them
}