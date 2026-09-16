rule TTP_XOR_MULT_DOSStub_0574 {
  strings:
    $key_0574 = { 51 1c [2] 25 04 [2] 62 06 [2] 25 17 [2] 6b 1b [2] 67 11 [2] 70 1a [2] 6b 54 [2] 56 }

  condition:
    any of them
}