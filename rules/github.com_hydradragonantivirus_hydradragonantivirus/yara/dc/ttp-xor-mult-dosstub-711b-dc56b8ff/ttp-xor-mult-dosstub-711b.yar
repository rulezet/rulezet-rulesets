rule TTP_XOR_MULT_DOSStub_711b {
  strings:
    $key_711b = { 25 73 [2] 51 6b [2] 16 69 [2] 51 78 [2] 1f 74 [2] 13 7e [2] 04 75 [2] 1f 3b [2] 22 }

  condition:
    any of them
}