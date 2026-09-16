rule TTP_XOR_MULT_DOSStub_6979 {
  strings:
    $key_6979 = { 3d 11 [2] 49 09 [2] 0e 0b [2] 49 1a [2] 07 16 [2] 0b 1c [2] 1c 17 [2] 07 59 [2] 3a }

  condition:
    any of them
}