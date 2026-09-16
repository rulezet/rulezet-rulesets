rule TTP_XOR_MULT_DOSStub_09a2 {
  strings:
    $key_09a2 = { 5d ca [2] 29 d2 [2] 6e d0 [2] 29 c1 [2] 67 cd [2] 6b c7 [2] 7c cc [2] 67 82 [2] 5a }

  condition:
    any of them
}