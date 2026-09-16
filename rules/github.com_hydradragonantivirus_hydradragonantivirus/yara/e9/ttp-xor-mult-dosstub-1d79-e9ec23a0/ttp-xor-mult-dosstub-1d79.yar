rule TTP_XOR_MULT_DOSStub_1d79 {
  strings:
    $key_1d79 = { 49 11 [2] 3d 09 [2] 7a 0b [2] 3d 1a [2] 73 16 [2] 7f 1c [2] 68 17 [2] 73 59 [2] 4e }

  condition:
    any of them
}