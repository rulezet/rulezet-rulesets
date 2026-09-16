rule TTP_XOR_MULT_DOSStub_1607 {
  strings:
    $key_1607 = { 42 6f [2] 36 77 [2] 71 75 [2] 36 64 [2] 78 68 [2] 74 62 [2] 63 69 [2] 78 27 [2] 45 }

  condition:
    any of them
}