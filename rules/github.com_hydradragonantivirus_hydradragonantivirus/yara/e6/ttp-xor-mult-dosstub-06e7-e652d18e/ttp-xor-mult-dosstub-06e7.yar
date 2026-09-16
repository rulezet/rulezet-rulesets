rule TTP_XOR_MULT_DOSStub_06e7 {
  strings:
    $key_06e7 = { 52 8f [2] 26 97 [2] 61 95 [2] 26 84 [2] 68 88 [2] 64 82 [2] 73 89 [2] 68 c7 [2] 55 }

  condition:
    any of them
}