rule TTP_XOR_MULT_DOSStub_6607 {
  strings:
    $key_6607 = { 32 6f [2] 46 77 [2] 01 75 [2] 46 64 [2] 08 68 [2] 04 62 [2] 13 69 [2] 08 27 [2] 35 }

  condition:
    any of them
}