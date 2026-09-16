rule TTP_XOR_MULT_DOSStub_6601 {
  strings:
    $key_6601 = { 32 69 [2] 46 71 [2] 01 73 [2] 46 62 [2] 08 6e [2] 04 64 [2] 13 6f [2] 08 21 [2] 35 }

  condition:
    any of them
}