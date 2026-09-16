rule TTP_XOR_MULT_DOSStub_5111 {
  strings:
    $key_5111 = { 05 79 [2] 71 61 [2] 36 63 [2] 71 72 [2] 3f 7e [2] 33 74 [2] 24 7f [2] 3f 31 [2] 02 }

  condition:
    any of them
}