rule TTP_XOR_MULT_DOSStub_5a1b {
  strings:
    $key_5a1b = { 0e 73 [2] 7a 6b [2] 3d 69 [2] 7a 78 [2] 34 74 [2] 38 7e [2] 2f 75 [2] 34 3b [2] 09 }

  condition:
    any of them
}