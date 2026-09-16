rule TTP_XOR_MULT_DOSStub_2268 {
  strings:
    $key_2268 = { 76 00 [2] 02 18 [2] 45 1a [2] 02 0b [2] 4c 07 [2] 40 0d [2] 57 06 [2] 4c 48 [2] 71 }

  condition:
    any of them
}