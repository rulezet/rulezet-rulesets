rule TTP_XOR_MULT_DOSStub_57e7 {
  strings:
    $key_57e7 = { 03 8f [2] 77 97 [2] 30 95 [2] 77 84 [2] 39 88 [2] 35 82 [2] 22 89 [2] 39 c7 [2] 04 }

  condition:
    any of them
}