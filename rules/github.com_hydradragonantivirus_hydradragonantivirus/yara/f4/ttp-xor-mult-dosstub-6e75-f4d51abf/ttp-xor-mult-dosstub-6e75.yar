rule TTP_XOR_MULT_DOSStub_6e75 {
  strings:
    $key_6e75 = { 3a 1d [2] 4e 05 [2] 09 07 [2] 4e 16 [2] 00 1a [2] 0c 10 [2] 1b 1b [2] 00 55 [2] 3d }

  condition:
    any of them
}