rule TTP_XOR_MULT_DOSStub_1707 {
  strings:
    $key_1707 = { 43 6f [2] 37 77 [2] 70 75 [2] 37 64 [2] 79 68 [2] 75 62 [2] 62 69 [2] 79 27 [2] 44 }

  condition:
    any of them
}