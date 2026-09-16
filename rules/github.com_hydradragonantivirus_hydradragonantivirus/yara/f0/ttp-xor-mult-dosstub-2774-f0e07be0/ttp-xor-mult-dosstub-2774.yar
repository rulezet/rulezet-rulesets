rule TTP_XOR_MULT_DOSStub_2774 {
  strings:
    $key_2774 = { 73 1c [2] 07 04 [2] 40 06 [2] 07 17 [2] 49 1b [2] 45 11 [2] 52 1a [2] 49 54 [2] 74 }

  condition:
    any of them
}