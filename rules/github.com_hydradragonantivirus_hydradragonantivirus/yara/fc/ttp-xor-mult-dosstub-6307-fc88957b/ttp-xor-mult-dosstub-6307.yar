rule TTP_XOR_MULT_DOSStub_6307 {
  strings:
    $key_6307 = { 37 6f [2] 43 77 [2] 04 75 [2] 43 64 [2] 0d 68 [2] 01 62 [2] 16 69 [2] 0d 27 [2] 30 }

  condition:
    any of them
}