rule TTP_XOR_MULT_DOSStub_6969 {
  strings:
    $key_6969 = { 3d 01 [2] 49 19 [2] 0e 1b [2] 49 0a [2] 07 06 [2] 0b 0c [2] 1c 07 [2] 07 49 [2] 3a }

  condition:
    any of them
}