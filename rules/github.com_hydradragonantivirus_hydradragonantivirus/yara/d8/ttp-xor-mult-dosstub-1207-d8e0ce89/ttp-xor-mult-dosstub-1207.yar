rule TTP_XOR_MULT_DOSStub_1207 {
  strings:
    $key_1207 = { 46 6f [2] 32 77 [2] 75 75 [2] 32 64 [2] 7c 68 [2] 70 62 [2] 67 69 [2] 7c 27 [2] 41 }

  condition:
    any of them
}