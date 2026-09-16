rule TTP_XOR_MULT_DOSStub_6d76 {
  strings:
    $key_6d76 = { 39 1e [2] 4d 06 [2] 0a 04 [2] 4d 15 [2] 03 19 [2] 0f 13 [2] 18 18 [2] 03 56 [2] 3e }

  condition:
    any of them
}