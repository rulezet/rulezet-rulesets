rule TTP_XOR_MULT_DOSStub_2136 {
  strings:
    $key_2136 = { 75 5e [2] 01 46 [2] 46 44 [2] 01 55 [2] 4f 59 [2] 43 53 [2] 54 58 [2] 4f 16 [2] 72 }

  condition:
    any of them
}