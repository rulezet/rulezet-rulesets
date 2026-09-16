rule TTP_XOR_MULT_DOSStub_6d1b {
  strings:
    $key_6d1b = { 39 73 [2] 4d 6b [2] 0a 69 [2] 4d 78 [2] 03 74 [2] 0f 7e [2] 18 75 [2] 03 3b [2] 3e }

  condition:
    any of them
}