rule TTP_XOR_MULT_DOSStub_6e46 {
  strings:
    $key_6e46 = { 3a 2e [2] 4e 36 [2] 09 34 [2] 4e 25 [2] 00 29 [2] 0c 23 [2] 1b 28 [2] 00 66 [2] 3d }

  condition:
    any of them
}