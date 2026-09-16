rule TTP_XOR_MULT_DOSStub_521b {
  strings:
    $key_521b = { 06 73 [2] 72 6b [2] 35 69 [2] 72 78 [2] 3c 74 [2] 30 7e [2] 27 75 [2] 3c 3b [2] 01 }

  condition:
    any of them
}