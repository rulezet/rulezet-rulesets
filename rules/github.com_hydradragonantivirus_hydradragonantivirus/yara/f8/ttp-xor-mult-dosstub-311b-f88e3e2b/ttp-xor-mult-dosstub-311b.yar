rule TTP_XOR_MULT_DOSStub_311b {
  strings:
    $key_311b = { 65 73 [2] 11 6b [2] 56 69 [2] 11 78 [2] 5f 74 [2] 53 7e [2] 44 75 [2] 5f 3b [2] 62 }

  condition:
    any of them
}