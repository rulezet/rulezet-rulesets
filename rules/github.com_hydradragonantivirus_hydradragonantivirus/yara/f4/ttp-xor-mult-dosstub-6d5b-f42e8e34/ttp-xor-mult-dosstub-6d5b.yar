rule TTP_XOR_MULT_DOSStub_6d5b {
  strings:
    $key_6d5b = { 39 33 [2] 4d 2b [2] 0a 29 [2] 4d 38 [2] 03 34 [2] 0f 3e [2] 18 35 [2] 03 7b [2] 3e }

  condition:
    any of them
}