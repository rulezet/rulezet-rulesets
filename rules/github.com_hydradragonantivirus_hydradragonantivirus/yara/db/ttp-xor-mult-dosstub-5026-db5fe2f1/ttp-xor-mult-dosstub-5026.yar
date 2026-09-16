rule TTP_XOR_MULT_DOSStub_5026 {
  strings:
    $key_5026 = { 04 4e [2] 70 56 [2] 37 54 [2] 70 45 [2] 3e 49 [2] 32 43 [2] 25 48 [2] 3e 06 [2] 03 }

  condition:
    any of them
}