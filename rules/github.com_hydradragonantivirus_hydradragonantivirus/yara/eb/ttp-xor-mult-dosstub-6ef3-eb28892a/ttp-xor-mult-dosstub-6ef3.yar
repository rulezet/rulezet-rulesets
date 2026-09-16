rule TTP_XOR_MULT_DOSStub_6ef3 {
  strings:
    $key_6ef3 = { 3a 9b [2] 4e 83 [2] 09 81 [2] 4e 90 [2] 00 9c [2] 0c 96 [2] 1b 9d [2] 00 d3 [2] 3d }

  condition:
    any of them
}