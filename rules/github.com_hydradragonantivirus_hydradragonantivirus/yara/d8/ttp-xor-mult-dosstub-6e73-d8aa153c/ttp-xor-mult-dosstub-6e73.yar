rule TTP_XOR_MULT_DOSStub_6e73 {
  strings:
    $key_6e73 = { 3a 1b [2] 4e 03 [2] 09 01 [2] 4e 10 [2] 00 1c [2] 0c 16 [2] 1b 1d [2] 00 53 [2] 3d }

  condition:
    any of them
}