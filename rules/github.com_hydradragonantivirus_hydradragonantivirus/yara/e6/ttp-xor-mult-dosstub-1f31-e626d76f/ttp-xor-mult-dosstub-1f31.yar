rule TTP_XOR_MULT_DOSStub_1f31 {
  strings:
    $key_1f31 = { 4b 59 [2] 3f 41 [2] 78 43 [2] 3f 52 [2] 71 5e [2] 7d 54 [2] 6a 5f [2] 71 11 [2] 4c }

  condition:
    any of them
}