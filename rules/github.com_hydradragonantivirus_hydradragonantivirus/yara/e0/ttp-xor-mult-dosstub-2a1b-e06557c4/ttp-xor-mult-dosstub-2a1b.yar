rule TTP_XOR_MULT_DOSStub_2a1b {
  strings:
    $key_2a1b = { 7e 73 [2] 0a 6b [2] 4d 69 [2] 0a 78 [2] 44 74 [2] 48 7e [2] 5f 75 [2] 44 3b [2] 79 }

  condition:
    any of them
}