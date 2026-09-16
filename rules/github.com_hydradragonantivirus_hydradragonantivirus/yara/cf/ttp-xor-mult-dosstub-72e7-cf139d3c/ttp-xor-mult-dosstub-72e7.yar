rule TTP_XOR_MULT_DOSStub_72e7 {
  strings:
    $key_72e7 = { 26 8f [2] 52 97 [2] 15 95 [2] 52 84 [2] 1c 88 [2] 10 82 [2] 07 89 [2] 1c c7 [2] 21 }

  condition:
    any of them
}