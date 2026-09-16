rule TTP_XOR_MULT_DOSStub_1657 {
  strings:
    $key_1657 = { 42 3f [2] 36 27 [2] 71 25 [2] 36 34 [2] 78 38 [2] 74 32 [2] 63 39 [2] 78 77 [2] 45 }

  condition:
    any of them
}