rule TTP_XOR_MULT_DOSStub_6ee2 {
  strings:
    $key_6ee2 = { 3a 8a [2] 4e 92 [2] 09 90 [2] 4e 81 [2] 00 8d [2] 0c 87 [2] 1b 8c [2] 00 c2 [2] 3d }

  condition:
    any of them
}