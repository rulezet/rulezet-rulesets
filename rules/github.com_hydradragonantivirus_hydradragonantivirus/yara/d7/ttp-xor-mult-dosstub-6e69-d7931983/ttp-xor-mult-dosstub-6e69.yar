rule TTP_XOR_MULT_DOSStub_6e69 {
  strings:
    $key_6e69 = { 3a 01 [2] 4e 19 [2] 09 1b [2] 4e 0a [2] 00 06 [2] 0c 0c [2] 1b 07 [2] 00 49 [2] 3d }

  condition:
    any of them
}