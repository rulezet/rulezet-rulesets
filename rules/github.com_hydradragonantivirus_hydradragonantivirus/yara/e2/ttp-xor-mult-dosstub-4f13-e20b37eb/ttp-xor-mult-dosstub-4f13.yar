rule TTP_XOR_MULT_DOSStub_4f13 {
  strings:
    $key_4f13 = { 1b 7b [2] 6f 63 [2] 28 61 [2] 6f 70 [2] 21 7c [2] 2d 76 [2] 3a 7d [2] 21 33 [2] 1c }

  condition:
    any of them
}