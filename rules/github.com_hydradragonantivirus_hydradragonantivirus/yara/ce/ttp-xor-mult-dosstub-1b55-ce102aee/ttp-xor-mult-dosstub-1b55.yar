rule TTP_XOR_MULT_DOSStub_1b55 {
  strings:
    $key_1b55 = { 4f 3d [2] 3b 25 [2] 7c 27 [2] 3b 36 [2] 75 3a [2] 79 30 [2] 6e 3b [2] 75 75 [2] 48 }

  condition:
    any of them
}