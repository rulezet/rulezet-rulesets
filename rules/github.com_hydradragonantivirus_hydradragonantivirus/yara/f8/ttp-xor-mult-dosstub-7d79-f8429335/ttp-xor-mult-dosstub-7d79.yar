rule TTP_XOR_MULT_DOSStub_7d79 {
  strings:
    $key_7d79 = { 29 11 [2] 5d 09 [2] 1a 0b [2] 5d 1a [2] 13 16 [2] 1f 1c [2] 08 17 [2] 13 59 [2] 2e }

  condition:
    any of them
}