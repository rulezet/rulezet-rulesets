rule TTP_XOR_MULT_DOSStub_1e44 {
  strings:
    $key_1e44 = { 4a 2c [2] 3e 34 [2] 79 36 [2] 3e 27 [2] 70 2b [2] 7c 21 [2] 6b 2a [2] 70 64 [2] 4d }

  condition:
    any of them
}