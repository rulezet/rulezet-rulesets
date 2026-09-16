rule TTP_XOR_MULT_DOSStub_3e65 {
  strings:
    $key_3e65 = { 6a 0d [2] 1e 15 [2] 59 17 [2] 1e 06 [2] 50 0a [2] 5c 00 [2] 4b 0b [2] 50 45 [2] 6d }

  condition:
    any of them
}