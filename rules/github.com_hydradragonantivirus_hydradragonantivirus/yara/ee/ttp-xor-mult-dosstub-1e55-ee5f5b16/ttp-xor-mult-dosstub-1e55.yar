rule TTP_XOR_MULT_DOSStub_1e55 {
  strings:
    $key_1e55 = { 4a 3d [2] 3e 25 [2] 79 27 [2] 3e 36 [2] 70 3a [2] 7c 30 [2] 6b 3b [2] 70 75 [2] 4d }

  condition:
    any of them
}