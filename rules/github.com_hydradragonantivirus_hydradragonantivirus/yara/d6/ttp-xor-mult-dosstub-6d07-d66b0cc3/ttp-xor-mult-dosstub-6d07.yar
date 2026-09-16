rule TTP_XOR_MULT_DOSStub_6d07 {
  strings:
    $key_6d07 = { 39 6f [2] 4d 77 [2] 0a 75 [2] 4d 64 [2] 03 68 [2] 0f 62 [2] 18 69 [2] 03 27 [2] 3e }

  condition:
    any of them
}