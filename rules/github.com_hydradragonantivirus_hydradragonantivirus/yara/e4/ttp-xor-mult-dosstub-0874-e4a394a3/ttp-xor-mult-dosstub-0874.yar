rule TTP_XOR_MULT_DOSStub_0874 {
  strings:
    $key_0874 = { 5c 1c [2] 28 04 [2] 6f 06 [2] 28 17 [2] 66 1b [2] 6a 11 [2] 7d 1a [2] 66 54 [2] 5b }

  condition:
    any of them
}