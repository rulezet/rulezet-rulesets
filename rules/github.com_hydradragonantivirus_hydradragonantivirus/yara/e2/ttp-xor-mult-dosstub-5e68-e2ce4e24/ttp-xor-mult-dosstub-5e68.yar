rule TTP_XOR_MULT_DOSStub_5e68 {
  strings:
    $key_5e68 = { 0a 00 [2] 7e 18 [2] 39 1a [2] 7e 0b [2] 30 07 [2] 3c 0d [2] 2b 06 [2] 30 48 [2] 0d }

  condition:
    any of them
}