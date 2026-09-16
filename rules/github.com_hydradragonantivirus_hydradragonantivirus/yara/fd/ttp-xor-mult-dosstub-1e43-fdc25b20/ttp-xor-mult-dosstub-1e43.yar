rule TTP_XOR_MULT_DOSStub_1e43 {
  strings:
    $key_1e43 = { 4a 2b [2] 3e 33 [2] 79 31 [2] 3e 20 [2] 70 2c [2] 7c 26 [2] 6b 2d [2] 70 63 [2] 4d }

  condition:
    any of them
}