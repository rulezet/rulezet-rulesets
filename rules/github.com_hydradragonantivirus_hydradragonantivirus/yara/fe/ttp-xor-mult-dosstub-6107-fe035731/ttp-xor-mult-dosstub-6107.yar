rule TTP_XOR_MULT_DOSStub_6107 {
  strings:
    $key_6107 = { 35 6f [2] 41 77 [2] 06 75 [2] 41 64 [2] 0f 68 [2] 03 62 [2] 14 69 [2] 0f 27 [2] 32 }

  condition:
    any of them
}