rule TTP_XOR_MULT_DOSStub_1e65 {
  strings:
    $key_1e65 = { 4a 0d [2] 3e 15 [2] 79 17 [2] 3e 06 [2] 70 0a [2] 7c 00 [2] 6b 0b [2] 70 45 [2] 4d }

  condition:
    any of them
}