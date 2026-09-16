rule TTP_XOR_MULT_DOSStub_3d79 {
  strings:
    $key_3d79 = { 69 11 [2] 1d 09 [2] 5a 0b [2] 1d 1a [2] 53 16 [2] 5f 1c [2] 48 17 [2] 53 59 [2] 6e }

  condition:
    any of them
}