rule TTP_XOR_MULT_DOSStub_7c68 {
  strings:
    $key_7c68 = { 28 00 [2] 5c 18 [2] 1b 1a [2] 5c 0b [2] 12 07 [2] 1e 0d [2] 09 06 [2] 12 48 [2] 2f }

  condition:
    any of them
}