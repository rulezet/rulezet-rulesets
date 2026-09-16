rule TTP_XOR_MULT_DOSStub_6e13 {
  strings:
    $key_6e13 = { 3a 7b [2] 4e 63 [2] 09 61 [2] 4e 70 [2] 00 7c [2] 0c 76 [2] 1b 7d [2] 00 33 [2] 3d }

  condition:
    any of them
}