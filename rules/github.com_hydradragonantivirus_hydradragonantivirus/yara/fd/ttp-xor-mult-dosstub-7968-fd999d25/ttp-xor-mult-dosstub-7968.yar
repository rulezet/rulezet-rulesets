rule TTP_XOR_MULT_DOSStub_7968 {
  strings:
    $key_7968 = { 2d 00 [2] 59 18 [2] 1e 1a [2] 59 0b [2] 17 07 [2] 1b 0d [2] 0c 06 [2] 17 48 [2] 2a }

  condition:
    any of them
}