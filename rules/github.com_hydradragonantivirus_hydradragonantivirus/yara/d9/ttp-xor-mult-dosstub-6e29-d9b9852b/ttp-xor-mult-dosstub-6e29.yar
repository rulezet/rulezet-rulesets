rule TTP_XOR_MULT_DOSStub_6e29 {
  strings:
    $key_6e29 = { 3a 41 [2] 4e 59 [2] 09 5b [2] 4e 4a [2] 00 46 [2] 0c 4c [2] 1b 47 [2] 00 09 [2] 3d }

  condition:
    any of them
}