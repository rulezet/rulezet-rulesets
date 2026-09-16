rule TTP_XOR_MULT_DOSStub_6864 {
  strings:
    $key_6864 = { 3c 0c [2] 48 14 [2] 0f 16 [2] 48 07 [2] 06 0b [2] 0a 01 [2] 1d 0a [2] 06 44 [2] 3b }

  condition:
    any of them
}