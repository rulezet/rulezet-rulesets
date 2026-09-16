rule TTP_XOR_MULT_DOSStub_7274 {
  strings:
    $key_7274 = { 26 1c [2] 52 04 [2] 15 06 [2] 52 17 [2] 1c 1b [2] 10 11 [2] 07 1a [2] 1c 54 [2] 21 }

  condition:
    any of them
}