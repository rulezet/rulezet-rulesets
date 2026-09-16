rule TTP_XOR_MULT_DOSStub_7913 {
  strings:
    $key_7913 = { 2d 7b [2] 59 63 [2] 1e 61 [2] 59 70 [2] 17 7c [2] 1b 76 [2] 0c 7d [2] 17 33 [2] 2a }

  condition:
    any of them
}