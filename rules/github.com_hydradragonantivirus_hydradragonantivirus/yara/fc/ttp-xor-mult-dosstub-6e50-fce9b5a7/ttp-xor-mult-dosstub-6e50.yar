rule TTP_XOR_MULT_DOSStub_6e50 {
  strings:
    $key_6e50 = { 3a 38 [2] 4e 20 [2] 09 22 [2] 4e 33 [2] 00 3f [2] 0c 35 [2] 1b 3e [2] 00 70 [2] 3d }

  condition:
    any of them
}