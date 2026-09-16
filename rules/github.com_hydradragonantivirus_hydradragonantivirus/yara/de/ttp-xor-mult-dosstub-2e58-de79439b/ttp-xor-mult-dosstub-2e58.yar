rule TTP_XOR_MULT_DOSStub_2e58 {
  strings:
    $key_2e58 = { 7a 30 [2] 0e 28 [2] 49 2a [2] 0e 3b [2] 40 37 [2] 4c 3d [2] 5b 36 [2] 40 78 [2] 7d }

  condition:
    any of them
}