rule TTP_XOR_MULT_DOSStub_2d13 {
  strings:
    $key_2d13 = { 79 7b [2] 0d 63 [2] 4a 61 [2] 0d 70 [2] 43 7c [2] 4f 76 [2] 58 7d [2] 43 33 [2] 7e }

  condition:
    any of them
}