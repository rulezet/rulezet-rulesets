rule TTP_XOR_MULT_DOSStub_031b {
  strings:
    $key_031b = { 57 73 [2] 23 6b [2] 64 69 [2] 23 78 [2] 6d 74 [2] 61 7e [2] 76 75 [2] 6d 3b [2] 50 }

  condition:
    any of them
}