rule TTP_XOR_MULT_DOSStub_7b1b {
  strings:
    $key_7b1b = { 2f 73 [2] 5b 6b [2] 1c 69 [2] 5b 78 [2] 15 74 [2] 19 7e [2] 0e 75 [2] 15 3b [2] 28 }

  condition:
    any of them
}