rule TTP_XOR_MULT_DOSStub_5874 {
  strings:
    $key_5874 = { 0c 1c [2] 78 04 [2] 3f 06 [2] 78 17 [2] 36 1b [2] 3a 11 [2] 2d 1a [2] 36 54 [2] 0b }

  condition:
    any of them
}